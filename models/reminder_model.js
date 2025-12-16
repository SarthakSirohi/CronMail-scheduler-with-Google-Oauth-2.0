import mongoose from "mongoose"

const reminderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User'},
    title: String,
    message: String,
    sendAt: { type: Date, required: true },
    sent: {type: Boolean, default: false}
})

const Reminder = mongoose.model('Reminder', reminderSchema)

export default Reminder