import { StreamChat } from "stream-chat";

const serverClient = StreamChat.getInstance(
    process.env.STREAM_API_KEY,
    process.env.STREAM_API_SECRET,
);

export function getStreamToken(userId) {
    if (!userId) throw new Error("Missing userId");
    return serverClient.createToken(userId);
}
