import * as randomBytes from 'randombytes';
import { sha512 } from 'js-sha512';
import { base64Encode, base64Decode } from './utils';
const sleep = (time: number) => new Promise(r => setTimeout(r, time));

const TOKEN_SIZE = 16;
const SIGNATURE_SIZE = 16;
const ZEROES = 4;
const zeroes = new Array(ZEROES).fill('0').join('');

export type ChallengeOptions = {
    hardness?: number
};

export type ValidationOptions = {
    expiration?: number
};

class NodeHashcash {

    createChallenge(secret: string, options: ChallengeOptions = {}): string {
        const {
            hardness = 8
        } = options;

        const token = this.generateToken(TOKEN_SIZE);
        const content = {
            token,
            hardness,
            iat: new Date().toISOString()
        };

        const signature = this.sign(content, secret);
        const challenge = { content, signature };

        return base64Encode(JSON.stringify(challenge));
    }

    async solveChallenge(challenge: string, onProgress: (progress: number) => void = () => {}): Promise<string> {
        const { content } = JSON.parse(base64Decode(challenge));
        const { token, hardness } = content;
        const solutions = [];

        onProgress(0);
        for(let i = 0; i < hardness; i++) {
            const solution = await this.findZeroes(`${i}:${token}`);
            solutions.push(solution);
            onProgress(solutions.length / hardness);
            await sleep(0);
        }

        return base64Encode(JSON.stringify(solutions));
    }

    validateChallenge(challenge: string, solution: string, secret: string, options: ValidationOptions = {}): boolean {
        const {
            expiration = 30000
        } = options;

        const solutions: string[] = JSON.parse(base64Decode(solution));
        const { content, signature } = JSON.parse(base64Decode(challenge));
        const { token, hardness, iat } = content;

        if(solutions.length > 64) {
            throw new Error("Too many solutions");
        }

        if(signature !== this.sign(content, secret)) {
            return false;
        }

        if(solutions.length !== hardness) {
            return false;
        }

        if(Date.now() - new Date(iat).getTime() > expiration) {
            return false;
        }

        return solutions.every((s, i) => this.validateSolution(s, i, token));
    }

    private validateSolution(solution: string, index: number, token: string): boolean {
        const value = `${solution}:${index}:${token}`;
        const hash = sha512(value);

        return hash.substring(0, ZEROES) === zeroes;
    }

    private sign(content: any, secret: string): string {
        return sha512(JSON.stringify(content) + secret).substring(0, SIGNATURE_SIZE);
    }

    private async findZeroes(token: string): Promise<string> {
        for(let attempt = 0; ; attempt++) {
            const value = `${attempt}:${token}`;
            const hash = sha512(value);

            if(attempt % 4e4 === 0) {
                await sleep(0);
            }

            if(hash.substring(0, ZEROES) === zeroes) {
                return attempt.toString();
            }
        }
    }

    private generateToken(size: number): string {
        if(size % 4 !== 0) {
            throw new Error('Token size must be a multiple of 4');
        }

        const bytes = 3 * size / 4;
        return randomBytes(bytes).toString('base64');
    }
}

export default new NodeHashcash();
