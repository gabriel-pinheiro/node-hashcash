import nodeHashcash from './index';
const sleep = (time: number) => new Promise(r => setTimeout(r, time));

describe('NodeHashcash', () => {
    const SECRET = 'my secret';

    it('should generate random tokens', () => {
        const firstValue = nodeHashcash['generateToken'](8);
        const secondValue = nodeHashcash['generateToken'](8);

        expect(firstValue).not.toBe(secondValue);
    });

    it('should generate correct sized tokens', () => {
        const LENGTH = 8;
        const token = nodeHashcash['generateToken'](LENGTH);

        expect(token.length).toBe(LENGTH);
    });

    it('should generate valid challenge', () => {
        const hardness = 7;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const challengeObj = JSON.parse(Buffer.from(challenge, 'base64').toString('ascii'));

        expect(challengeObj.signature.length).toBe(16);
        expect(challengeObj.content.token.length).toBe(16);
        expect(challengeObj.content.hardness).toBe(hardness);
        expect(challengeObj.content.iat.length).not.toBe(0);
    });

    it('should give the correct amount of solutions to a challenge', async () => {
        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const solution = await nodeHashcash.solveChallenge(challenge);
        const solutions = JSON.parse(Buffer.from(solution, 'base64').toString('ascii'));

        expect(solutions.length).toBe(hardness);
    });

    it('should update onProgress correctly', async () => {
        const updates = [];
        let last = -1;

        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        await nodeHashcash.solveChallenge(challenge, progress => {
            expect(progress).toBeGreaterThan(last);
            updates.push(progress);
        });

        expect(updates.length).toBe(hardness + 1);
    });

    it('should validate correctly solved challenge', async () => {
        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const solution = await nodeHashcash.solveChallenge(challenge);
        const isValid = nodeHashcash.validateChallenge(challenge, solution, SECRET);

        expect(isValid).toBe(true);
    });

    it('should not validate wrong signature', async () => {
        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const solution = await nodeHashcash.solveChallenge(challenge);
        const isValid = nodeHashcash.validateChallenge(challenge, solution, 'wrong secret');

        expect(isValid).toBe(false);
    });

    it('should not validate wrong solutions', async () => {
        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const solution = Buffer.from(JSON.stringify(['0', '0', '0']), 'binary').toString('base64');
        const isValid = nodeHashcash.validateChallenge(challenge, solution, SECRET);

        expect(isValid).toBe(false);
    });

    it('should not validate expired solution', async () => {
        const hardness = 3;
        const challenge = nodeHashcash.createChallenge(SECRET, { hardness });
        const solution = await nodeHashcash.solveChallenge(challenge);
        await sleep(200);
        const isValid = nodeHashcash.validateChallenge(challenge, solution, SECRET, {
            expiration: 200
        });

        expect(isValid).toBe(false);
    });
});
