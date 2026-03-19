/** @internal */
export class StringUtility {
    private constructor() { }

    static stringToArrayBuffer(dto: { string: string; encoding: BufferEncoding; }): ArrayBuffer {
        const { string, encoding } = dto;
        const buffer = Uint8Array.from(Buffer.from(string, encoding)).buffer;
        if (buffer instanceof ArrayBuffer) {
            return buffer;
        }
        throw new Error("Generated buffer is not an ArrayBuffer");
    }

    static arrayBufferToString(dto: { buffer: ArrayBuffer; encoding: BufferEncoding }) {
        const { buffer, encoding } = dto;
        return Buffer.from(buffer).toString(encoding);
    }
}