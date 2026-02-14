import mongoose, { Document, Schema } from 'mongoose';

export interface IConversation extends Document {
  members: mongoose.Types.ObjectId[];
  lastMessage?: string;
  lastTimestamp?: number;
}

const ConversationSchema: Schema = new Schema({
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessage: { type: String },
  lastTimestamp: { type: Number, default: Date.now },
});

export default mongoose.model<IConversation>('Conversation', ConversationSchema);
