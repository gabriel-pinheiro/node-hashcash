export function base64Encode(value: string): string {
    if(typeof btoa === 'function') {
        return btoa(value);
    }

    return Buffer.from(value, 'binary').toString('base64');
}

export function base64Decode(value: string): string {
    if(typeof atob === 'function') {
        return atob(value);
    }

    return Buffer.from(value, 'base64').toString('ascii');
}
