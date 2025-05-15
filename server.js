const http = require('http');
const express = require('express');
const mongoose = require('mongoose');
const faye = require('faye');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const bcryptjs = require('bcryptjs');
const path = require('path');
// const Pusher = require('pusher'); // Dihapus

const app = express();
const server = http.createServer(app);
const saltRounds = 10;

const bayeux = new faye.NodeAdapter({ mount: '/faye', timeout: 45 });
bayeux.attach(server);
const fayeClient = bayeux.getClient();

// Inisialisasi Pusher Dihapus
// const pusher = new Pusher({ ... });

mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://zanssxploit:pISqUYgJJDfnLW9b@cluster0.fgram.mongodb.net/restdb?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Connection Error:', err));

// Skema Model (tetap sama seperti sebelumnya)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    displayName: { type: String, trim: true },
    profilePictureUrl: { type: String, default: '' },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    bio: { type: String, trim: true, maxlength: 150, default: '' },
    email: { type: String, trim: true, lowercase: true, unique: true, sparse: true },
    online: { type: Boolean, default: false },
    lastSeen: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
userSchema.virtual('displayUsername').get(function() { return this.displayName || this.username; });
const User = mongoose.model('User', userSchema);

const channelSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true, default: '' },
    creator: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    isPrivate: { type: Boolean, default: false },
    topic: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});
channelSchema.index({ name: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
const Channel = mongoose.model('Channel', channelSchema);

const messageSchema = new mongoose.Schema({
    user: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true, trim: true },
    channelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel' },
    isEdited: { type: Boolean, default: false },
    reactions: [{ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, emoji: String }],
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

const friendRequestSchema = new mongoose.Schema({
    requester: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'declined', 'blocked'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});
friendRequestSchema.index({ requester: 1, recipient: 1 }, { unique: true });
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);

const notificationSchema = new mongoose.Schema({
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, required: true, enum: ['friend_request_sent', 'friend_request_accepted', 'new_message_in_channel', 'new_direct_message', 'channel_invite', 'mention'] },
    message: String,
    link: String,
    entityId: { type: mongoose.Schema.Types.ObjectId },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
notificationSchema.index({ recipient: 1, isRead: 1, createdAt: -1 });
const Notification = mongoose.model('Notification', notificationSchema);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function requireAuth(req, res, next) {
    if (!req.cookies.username) return res.redirect('/login');
    try {
        const user = await User.findOne({ username: req.cookies.username });
        if (!user) {
            res.clearCookie('username');
            return res.redirect('/login');
        }
        req.user = user;
        next();
    } catch (error) {
        console.error("Auth middleware error:", error);
        res.clearCookie('username');
        return res.redirect('/login');
    }
}

async function createAndSendNotification(recipientId, type, message, link = '#', senderId = null, entityId = null) {
    try {
        const notification = new Notification({ recipient: recipientId, type, message, link, sender: senderId, entityId });
        await notification.save();
        const notifChannelFaye = `/users/${recipientId}/notifications`;
        fayeClient.publish(notifChannelFaye, { type: 'new_notification', notification });
        // pusher.trigger(...); // Dihapus
    } catch (error) {
        console.error("Error creating notification:", error);
    }
}

app.get('/', (req, res) => req.cookies.username ? res.redirect('/chat') : res.redirect('/login'));
app.get('/login', (req, res) => req.cookies.username ? res.redirect('/chat') : res.render('login', { error: null }));
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.render('login', { error: 'Nama pengguna dan password harus diisi.' });
    try {
        const user = await User.findOne({ username: username.toLowerCase() });
        if (!user) return res.render('login', { error: 'Nama pengguna atau password salah.' });
        const isMatch = await bcryptjs.compare(password, user.password);
        if (!isMatch) return res.render('login', { error: 'Nama pengguna atau password salah.' });
        user.online = true; user.lastSeen = new Date(); await user.save();
        res.cookie('username', user.username, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000 });
        res.redirect('/chat');
    } catch (err) { console.error("Login error:", err); res.render('login', { error: 'Terjadi kesalahan server.' }); }
});
app.get('/register', (req, res) => req.cookies.username ? res.redirect('/chat') : res.render('register', { error: null, success: null }));
app.post('/register', async (req, res) => {
    const { username, password, confirmPassword, email, displayName } = req.body;
    if (!username || !password || !confirmPassword) return res.render('register', { error: 'Semua field wajib diisi.', success: null });
    if (password !== confirmPassword) return res.render('register', { error: 'Password tidak cocok.', success: null });
    if (password.length < 6) return res.render('register', { error: 'Password minimal 6 karakter.', success: null });
    try {
        let existingUser = await User.findOne({ username: username.toLowerCase() });
        if (existingUser) return res.render('register', { error: 'Nama pengguna sudah ada.', success: null });
        if (email && email.trim() !== '') {
            existingUser = await User.findOne({ email: email.toLowerCase() });
            if (existingUser) return res.render('register', { error: 'Email sudah terdaftar.', success: null });
        }
        const hashedPassword = await bcryptjs.hash(password, saltRounds);
        const newUser = new User({
            username: username.toLowerCase(), password: hashedPassword,
            email: email ? email.toLowerCase().trim() : undefined,
            displayName: displayName ? displayName.trim() : username.trim()
        });
        await newUser.save();
        res.render('register', { error: null, success: 'Registrasi berhasil! Silakan login.' });
    } catch (err) { console.error("Register error:", err); res.render('register', { error: 'Terjadi kesalahan saat registrasi.', success: null }); }
});
app.get('/logout', requireAuth, async (req, res) => {
    try {
        if (req.user) { req.user.online = false; req.user.lastSeen = new Date(); await req.user.save(); }
    } catch(error) { console.error("Error updating user status on logout:", error); }
    res.clearCookie('username');
    res.redirect('/login');
});

app.get('/chat', requireAuth, async (req, res) => {
    try {
        const messages = await Message.find({ channelId: null }).populate('userId', 'displayUsername profilePictureUrl').sort({ timestamp: 1 }).limit(100);
        const unreadNotificationsCount = req.user ? await Notification.countDocuments({ recipient: req.user._id, isRead: false }) : 0;
        res.render('chat', {
            messages: messages, username: req.user.displayUsername, userId: req.user._id.toString(),
            // pusherKey dan pusherCluster dihapus dari data yang dikirim ke EJS
            activePage: 'chat', currentChannel: null, currentUser: req.user,
            unreadNotificationsCount: unreadNotificationsCount
        });
    } catch (err) { console.error("Error loading general chat:", err); res.status(500).send("Error loading general chat. Check server logs."); }
});

app.post('/messages', requireAuth, async (req, res) => {
    const { text, channelId } = req.body;
    if (!text || text.trim() === '') return res.status(400).json({ error: 'Pesan tidak boleh kosong' });
    try {
        let targetChannel = null;
        if (channelId && channelId !== 'null' && mongoose.Types.ObjectId.isValid(channelId)) {
            targetChannel = await Channel.findById(channelId);
            if (!targetChannel) return res.status(404).json({ error: 'Channel tidak ditemukan' });
            const isMember = targetChannel.members.some(memberId => memberId.equals(req.user._id)) || targetChannel.creator.equals(req.user._id);
            if (targetChannel.isPrivate && !isMember) return res.status(403).json({ error: 'Anda bukan anggota channel privat ini' });
        }
        const newMessage = new Message({
            user: req.user.displayUsername, userId: req.user._id, text: text.trim(),
            channelId: targetChannel ? targetChannel._id : null
        });
        const savedMessage = await newMessage.save();
        const populatedMessage = await Message.findById(savedMessage._id).populate('userId', 'displayUsername profilePictureUrl');
        const messageData = {
            _id: populatedMessage._id.toString(), user: populatedMessage.user, text: populatedMessage.text,
            userId: populatedMessage.userId._id.toString(), userDisplayUsername: populatedMessage.userId.displayUsername,
            userProfilePictureUrl: populatedMessage.userId.profilePictureUrl,
            channelId: populatedMessage.channelId ? populatedMessage.channelId.toString() : null,
            timestamp: populatedMessage.timestamp, isEdited: populatedMessage.isEdited
        };
        const fayePublishPath = targetChannel ? `/channels/${targetChannel._id}/messages` : '/messages/new';
        fayeClient.publish(fayePublishPath, messageData);
        // pusher.trigger(...); // Dihapus

        if (targetChannel) {
            targetChannel.members.forEach(memberId => {
                if (!memberId.equals(req.user._id)) {
                    createAndSendNotification(memberId, 'new_message_in_channel',
                        `${req.user.displayUsername} mengirim pesan di #${targetChannel.name}`,
                        `/channels/${targetChannel._id}`, req.user._id, targetChannel._id);
                }
            });
        }
        res.status(201).json(populatedMessage);
    } catch (err) { console.error("Error sending message:", err); res.status(500).json({ error: 'Gagal mengirim pesan' }); }
});

app.get('/channels', requireAuth, async (req, res) => {
    try {
        const channels = await Channel.find({ $or: [{ isPrivate: false }, { members: req.user._id }, { creator: req.user._id }]})
                                     .populate('creator', 'displayUsername').sort({ name: 1 });
        const unreadNotificationsCount = req.user ? await Notification.countDocuments({ recipient: req.user._id, isRead: false }) : 0;
        res.render('channels', {
            username: req.user.displayUsername, userId: req.user._id.toString(), channels, activePage: 'channels',
            error: req.query.error, success: req.query.success, currentUser: req.user,
            unreadNotificationsCount: unreadNotificationsCount
        });
    } catch (err) { console.error("Error loading channels:", err); res.status(500).send("Error loading channels"); }
});
app.post('/channels', requireAuth, async (req, res) => {
    const { name, description, isPrivate } = req.body;
    if (!name || name.trim() === '') return res.redirect('/channels?error=Nama channel tidak boleh kosong');
    try {
        const existingChannel = await Channel.findOne({ name: { $regex: new RegExp(`^${name.trim()}$`, 'i') } });
        if (existingChannel) return res.redirect('/channels?error=Nama channel sudah ada');
        const newChannel = new Channel({
            name: name.trim(), description: description ? description.trim() : '', isPrivate: !!isPrivate,
            creator: req.user._id, members: [req.user._id]
        });
        await newChannel.save();
        res.redirect(`/channels/${newChannel._id}?success=Channel ${newChannel.name} berhasil dibuat`);
    } catch (err) { console.error("Error creating channel:", err); res.redirect('/channels?error=Gagal membuat channel'); }
});
app.get('/channels/:id', requireAuth, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
             return res.status(400).render('404', { message: 'ID Channel tidak valid', username: req.user.displayUsername, currentUser: req.user });
        }
        const channel = await Channel.findById(req.params.id).populate('creator', 'displayUsername').populate('members', 'displayUsername profilePictureUrl');
        if (!channel) return res.status(404).render('404', { message: 'Channel tidak ditemukan', username: req.user.displayUsername, currentUser: req.user });
        const isMember = channel.members.some(m => m._id.equals(req.user._id)) || channel.creator._id.equals(req.user._id);
        if (channel.isPrivate && !isMember) return res.status(403).render('403', { message: 'Akses ditolak ke channel privat ini', username: req.user.displayUsername, currentUser: req.user });
        const messages = await Message.find({ channelId: channel._id }).populate('userId', 'displayUsername profilePictureUrl').sort({ timestamp: 1 }).limit(100);
        const unreadNotificationsCount = req.user ? await Notification.countDocuments({ recipient: req.user._id, isRead: false }) : 0;
        res.render('chat', { // Menggunakan template chat.ejs untuk detail channel
            username: req.user.displayUsername, userId: req.user._id.toString(), messages, isMember,
            // pusherKey dan pusherCluster dihapus
            activePage: 'channels', currentChannel: channel, currentUser: req.user,
            unreadNotificationsCount: unreadNotificationsCount
        });
    } catch (err) { console.error("Error loading channel detail:", err); res.status(500).send("Error loading channel details"); }
});
app.post('/channels/:id/join', requireAuth, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.redirect(`/channels?error=ID Channel tidak valid`);
        const channel = await Channel.findById(req.params.id);
        if (!channel) return res.status(404).redirect(`/channels?error=Channel tidak ditemukan`);
        if (channel.isPrivate) return res.status(403).redirect(`/channels/${req.params.id}?error=Tidak bisa join channel privat secara langsung`);
        const isAlreadyMember = channel.members.some(memberId => memberId.equals(req.user._id));
        if (!isAlreadyMember) {
            channel.members.push(req.user._id);
            await channel.save();
            await createAndSendNotification(channel.creator, 'channel_invite',
                `${req.user.displayUsername} bergabung ke channel #${channel.name}`,
                `/channels/${channel._id}`, req.user._id, channel._id);
        }
        res.redirect(`/channels/${channel._id}?success=Berhasil bergabung`);
    } catch (err) { console.error("Error joining channel:", err); res.redirect(`/channels?error=Gagal bergabung ke channel`); }
});

app.get('/friends', requireAuth, async (req, res) => {
    try {
        const userWithFriends = await User.findById(req.user._id).populate('friends', 'displayUsername profilePictureUrl online lastSeen');
        const pendingRequestsSent = await FriendRequest.find({ requester: req.user._id, status: 'pending' }).populate('recipient', 'displayUsername profilePictureUrl');
        const pendingRequestsReceived = await FriendRequest.find({ recipient: req.user._id, status: 'pending' }).populate('requester', 'displayUsername profilePictureUrl');
        const friendIds = userWithFriends.friends.map(f => f._id);
        const sentRequestRecipientIds = pendingRequestsSent.map(r => r.recipient._id);
        const receivedRequestRequesterIds = pendingRequestsReceived.map(r => r.requester._id);
        const excludedIds = [req.user._id, ...friendIds, ...sentRequestRecipientIds, ...receivedRequestRequesterIds];
        const allUsers = await User.find({ _id: { $nin: excludedIds } }).select('displayUsername username profilePictureUrl').limit(20);
        const unreadNotificationsCount = req.user ? await Notification.countDocuments({ recipient: req.user._id, isRead: false }) : 0;
        res.render('friends', {
            username: req.user.displayUsername, userId: req.user._id.toString(), friends: userWithFriends.friends,
            requestsSent: pendingRequestsSent, requestsReceived: pendingRequestsReceived, allUsers,
            activePage: 'friends', error: req.query.error, success: req.query.success, currentUser: req.user,
            unreadNotificationsCount: unreadNotificationsCount
        });
    } catch (err) { console.error("Error loading friends page:", err); res.status(500).send("Error loading friends page"); }
});
app.post('/friends/request/:recipientId', requireAuth, async (req, res) => {
    const recipientId = req.params.recipientId;
    if (!mongoose.Types.ObjectId.isValid(recipientId)) return res.redirect('/friends?error=ID Pengguna tidak valid');
    if (req.user._id.equals(recipientId)) return res.redirect('/friends?error=Tidak bisa berteman dengan diri sendiri');
    try {
        const recipient = await User.findById(recipientId);
        if (!recipient) return res.redirect('/friends?error=Pengguna tidak ditemukan');
        const alreadyFriends = req.user.friends.some(friendId => friendId.equals(recipientId));
        if (alreadyFriends) return res.redirect('/friends?error=Sudah berteman dengan pengguna ini');
        const existingRequest = await FriendRequest.findOne({
            $or: [ { requester: req.user._id, recipient: recipientId }, { requester: recipientId, recipient: req.user._id } ]
        });
        if (existingRequest && existingRequest.status === 'pending') return res.redirect('/friends?error=Permintaan pertemanan sudah ada');
        if (existingRequest && existingRequest.status === 'accepted') return res.redirect('/friends?error=Anda sudah berteman');
        if (existingRequest && (existingRequest.status === 'declined' || existingRequest.status === 'blocked')) {
             if(existingRequest.requester.equals(req.user._id)) {
                existingRequest.status = 'pending'; existingRequest.recipient = recipientId; existingRequest.requester = req.user._id;
                await existingRequest.save();
             } else { return res.redirect('/friends?error=Tidak bisa mengirim permintaan ke pengguna ini saat ini.'); }
        } else if (!existingRequest) {
            await FriendRequest.create({ requester: req.user._id, recipient: recipientId });
        }
        await createAndSendNotification(recipientId, 'friend_request_sent',
            `${req.user.displayUsername} mengirim permintaan pertemanan.`, '/friends', req.user._id, req.user._id);
        res.redirect('/friends?success=Permintaan pertemanan terkirim');
    } catch (err) { console.error("Error sending friend request:", err); res.redirect('/friends?error=Gagal mengirim permintaan'); }
});
app.post('/friends/respond/:requestId', requireAuth, async (req, res) => {
    const { action } = req.body;
    const requestId = req.params.requestId;
    if (!mongoose.Types.ObjectId.isValid(requestId)) return res.redirect('/friends?error=ID Permintaan tidak valid');
    try {
        const request = await FriendRequest.findById(requestId);
        if (!request || !request.recipient.equals(req.user._id) || request.status !== 'pending') {
            return res.redirect('/friends?error=Permintaan tidak valid atau sudah direspon');
        }
        if (action === 'accept') {
            request.status = 'accepted';
            await User.findByIdAndUpdate(request.requester, { $addToSet: { friends: request.recipient } });
            await User.findByIdAndUpdate(request.recipient, { $addToSet: { friends: request.requester } });
            await createAndSendNotification(request.requester, 'friend_request_accepted',
                `${req.user.displayUsername} menerima permintaan pertemanan Anda.`, '/friends', req.user._id, req.user._id);
            res.redirect('/friends?success=Permintaan pertemanan diterima');
        } else if (action === 'decline') {
            request.status = 'declined';
            res.redirect('/friends?success=Permintaan pertemanan ditolak');
        } else { return res.redirect('/friends?error=Aksi tidak valid'); }
        await request.save();
    } catch (err) { console.error("Error responding to friend request:", err); res.redirect('/friends?error=Gagal merespon permintaan'); }
});

app.get('/notifications', requireAuth, async (req, res) => {
    try {
        const notifications = await Notification.find({ recipient: req.user._id })
                                            .populate('sender', 'displayUsername profilePictureUrl')
                                            .sort({ createdAt: -1 }).limit(50);
        const unreadNotificationsCount = notifications.filter(n => !n.isRead).length;
        res.render('notifications', {
            username: req.user.displayUsername, userId: req.user._id.toString(), notifications, activePage: 'notifications',
            currentUser: req.user, unreadNotificationsCount: unreadNotificationsCount
        });
    } catch (err) { console.error("Error loading notifications:", err); res.status(500).send("Error loading notifications"); }
});
app.post('/notifications/:id/read', requireAuth, async (req, res) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ID Notifikasi tidak valid' });
    try {
        const notification = await Notification.findOneAndUpdate(
            { _id: req.params.id, recipient: req.user._id }, { isRead: true }, { new: true }
        );
        if (!notification) return res.status(404).json({ error: 'Notifikasi tidak ditemukan' });
        res.json({ success: true, notification });
    } catch (err) { console.error("Error marking notification as read:", err); res.status(500).json({ error: 'Gagal menandai notifikasi' }); }
});
app.post('/notifications/read-all', requireAuth, async (req, res) => {
    try {
        await Notification.updateMany({ recipient: req.user._id, isRead: false }, { $set: { isRead: true } });
        res.json({ success: true, message: 'Semua notifikasi ditandai terbaca' });
    } catch (err) { console.error("Error marking all notifications as read:", err); res.status(500).json({ error: 'Gagal menandai semua notifikasi' }); }
});

app.get('/settings', requireAuth, async (req, res) => {
    const unreadNotificationsCount = req.user ? await Notification.countDocuments({ recipient: req.user._id, isRead: false }) : 0;
    res.render('settings', {
        username: req.user.displayUsername, userId: req.user._id.toString(),
        currentUser: req.user, activePage: 'settings',
        error: req.query.error, success: req.query.success,
        unreadNotificationsCount: unreadNotificationsCount
    });
});
app.post('/settings', requireAuth, async (req, res) => {
    const { displayName, bio, email, newPassword, confirmNewPassword, profilePictureUrl } = req.body;
    try {
        const userToUpdate = await User.findById(req.user._id);
        if (!userToUpdate) return res.redirect('/settings?error=Pengguna tidak ditemukan');
        if (displayName && displayName.trim() !== '') userToUpdate.displayName = displayName.trim();
        if (bio !== undefined) userToUpdate.bio = bio.trim();
        if (profilePictureUrl !== undefined) userToUpdate.profilePictureUrl = profilePictureUrl.trim();
        if (email && email.trim() !== '' && email.trim().toLowerCase() !== userToUpdate.email) {
            const emailExists = await User.findOne({ email: email.trim().toLowerCase(), _id: { $ne: userToUpdate._id } });
            if (emailExists) return res.redirect('/settings?error=Email sudah digunakan pengguna lain');
            userToUpdate.email = email.trim().toLowerCase();
        }
        if (newPassword && newPassword.trim() !== '') {
            if (newPassword.length < 6) return res.redirect('/settings?error=Password baru minimal 6 karakter');
            if (newPassword !== confirmNewPassword) return res.redirect('/settings?error=Konfirmasi password baru tidak cocok');
            userToUpdate.password = await bcryptjs.hash(newPassword, saltRounds);
        }
        await userToUpdate.save();
        res.redirect('/settings?success=Pengaturan berhasil disimpan');
    } catch (error) { console.error("Error updating settings:", error); res.redirect('/settings?error=Gagal menyimpan pengaturan'); }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Faye server mounted at /faye`);
    console.log("Pusher integration has been removed/disabled in this version.");
});