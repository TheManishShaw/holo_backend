import mongoose, { Document, Schema } from 'mongoose';

export interface IChatMessage extends Document {
  conversationId: string;
  sender: mongoose.Types.ObjectId;
  body: string;
  timestamp: number;
  deliveredAt?: number;
  readAt?: number;
}

const ChatMessageSchema: Schema = new Schema({
  conversationId: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  body: { type: String, required: true },
  timestamp: { type: Number, default: Date.now },
  deliveredAt: { type: Number },
  readAt: { type: Number },
});

export default mongoose.model<IChatMessage>('ChatMessage', ChatMessageSchema);
