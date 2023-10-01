import express from "express";
import mongoose, { Schema } from "mongoose";
import dotenv from "dotenv";
import multer from "multer";
import cors from "cors";
import path from "path";
import bcrypt from 'bcrypt'
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser";








const salt = 10;
const app = express();
dotenv.config();
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));
// app.use(cors({
//     origin: ['http://localhost:3000'],
//     method: ["POST", "GET", "DELETE"],
//     credentials: true
// }))
app.use("*", cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"]
}),
    function (req, res, next) {
        req.header('Access-Control-Allow-Origin', req.origin),
            req.header('Access-Control-Allow-Headers', "Origin,X-Requested-With,Content-Type")
        next()
    })

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, 'public/images')
        },
        filename: (req, file, cb) => {
            cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
        }
    })
});

// const multerConfig = upload.fields([
//     { name: 'photos[]', maxCount: 6 }
// ])

var multipleUpload = upload.fields([{ name: "image1" }, { name: "image2" }, { name: "image3" }, { name: "image4" }, { name: "image5" }]);

// await mongoose.connect('mongodb://localhost:27017/travel-app');

const db = 'mongodb+srv://gajendra34:gajendra34@cluster0.ly6grc2.mongodb.net/travelapp?retryWrites=true&w=majority'
mongoose.connect(db, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('mongodb(atlas) connection successfully')
}).catch(err => console.log('no connection', err))

const signupSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    image: String
});

const addplaceSchema = new mongoose.Schema({
    category: String,
    city: String,
    country: String,
    rating: String,
    about: String,
    price: String,
    owner: String,
    image1: String,
    image2: String,
    image3: String,
    image4: String,
    image5: String
});

const pay_detailSchema = new mongoose.Schema({
    email: String,
    name: String,
    phone: String,
    price: String,
    login_id: String,
    chk_in: String,
    chk_out: String,
    pro_id: String,
    stay_day: String,
    paymentstatus: String
});

const otpSchema = new mongoose.Schema({
    email: String,
    otpcode: String,
    expiresIn: Number
})

const paymentHistory = new mongoose.Schema({
    cardname: String,
    cardnumber: String,
    expire: String,
    cvv: String,
    Tprice: String,
    paymentstatus: String
})


const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "Yor are not Authenticated" })
    }
    else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" })
            req.role = decoded.role;
            req.id = decoded.id;
            req.image = decoded.image;
            req.name = decoded.name;
            next();
        })
    }
}

app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: "Success", role: req.role, id: req.id, image: req.image, name: req.name })
})


import nodemailer from 'nodemailer'
var transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    requireTLS: true,
    sedrvice: 'gmail',
    auth: {
        user: 'u21cs035@coed.svnit.ac.in',
        pass: 'NIT05-08-2001'
    }
})


app.post('/signup', upload.single('image'), async (req, res) => {
    const model = new mongoose.model('signup', signupSchema);
    // const { name, email, password, image } = req.body;

    await bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error for hashing password" })
        // console.log(hash);
    })

    if (!req.body.name.length || !req.body.password.length || !req.body.email.length) {
        return res.json({ Error: "Please enter details" })
    }

    const data = await model.find({ email: req.body.email });
    if (data.length) {
        return res.json({ Error: "Email already exist! please enter new email" })
    }

    const data1 = new model({ name: req.body.name, email: req.body.email, password: req.body.password, image: req.file.filename })
    const result = await data1.save();
    var mailOption1 = {
        from: 'u21cs035@coed.svnit.ac.in',
        to: req.body.email,
        subject: 'Thanks For Create account',
        html: '<p><b>You are welcome in airRv_travel service</b><br/><br/><b>Thank You!</b></p>'
    }
    transporter.sendMail(mailOption1, (err, info) => {
        if (err) return res.json({ Error: "msg send Error in server " });
        // console.log('successfull', info.response)
        return res.json({ Status: "Success" })
    })
})

app.post('/login', async (req, res) => {
    const model = new mongoose.model('signup', signupSchema);
    if (!req.body.password.length || !req.body.email.length) {
        return res.json({ Error: "Please enter details" })
    }
    const result = await model.find({ email: req.body.email });
    if (result.length > 0) {
        const newHashedPassword = await bcrypt.hash(req.body.password.toString(), salt);
        await bcrypt.compare(result[0].password, newHashedPassword, async (err, resp) => {
            if (err) return res.json({ Error: "Password compare error" });
            if (resp) {
                // const id = result[0].id;
                const token = jwt.sign({ role: "customer", id: result[0]._id, image: result[0].image, name: result[0].name }, "jwt-secret-key", { expiresIn: '1d' });
                res.cookie('token', token, {
                    sameSite: 'none',
                    secure: true,
                    httpOnly: true
                });
                return res.json({ Status: "Success" });
            }
            else {
                return res.json({ Error: "Password not matched" });
            }
        })
    }
    else {
        return res.json({ Status: "Error", Error: "Wrong Email and Password" })
    }
})

app.get('/logout', (req, res) => {
    res.cookie('token', null, {
        sameSite: 'none',
        secure: true,
        httpOnly: true
    });
    return res.json({ Status: "Success" })
})


// places/Category--->Start



app.post('/addplace', multipleUpload, async (req, res) => {
    const model = new mongoose.model('addplace', addplaceSchema);
    // const { name, email, password, image } = req.body;

    if (!req.body.category.length || !req.body.city.length || !req.body.country.length || !req.body.rating.length || !req.body.about.length || !req.body.price.length || !req.body.owner.length) {
        return res.json({ Error: "Please enter details" })
    }

    const data = new model({ category: req.body.category, city: req.body.city, country: req.body.country, rating: req.body.rating, about: req.body.about, price: req.body.price, owner: req.body.owner, image1: req.files['image1'][0].filename, image2: req.files['image2'][0].filename, image3: req.files['image3'][0].filename, image4: req.files['image4'][0].filename, image5: req.files['image5'][0].filename })
    const result = await data.save();
    return res.json({ Status: "Success" })

})

app.get('/Aview', async (req, res) => {
    const model = new mongoose.model('addplace', addplaceSchema);
    const result = await model.find({ category: 'Amazingviews' });
    res.json({ Result: result, Status: 'Success' })
})

app.get('/showImg/:id', async (req, res) => {
    const id = req.params.id;
    const model = new mongoose.model('addplace', addplaceSchema);
    const result = await model.find({ _id: id });
    res.json({ Result: result, Status: 'Success' })
})

app.get('/showplaces/:category', async (req, res) => {
    const cate = req.params.category;
    const model = new mongoose.model('addplace', addplaceSchema);
    const result = await model.find({ category: cate });
    res.json({ Result: result, Status: 'Success' })
})

app.get('/placedetail/:id', async (req, res) => {
    const id = req.params.id;
    const model = new mongoose.model('addplace', addplaceSchema);
    const result = await model.find({ _id: id });
    res.json({ Result: result, Status: 'Success' })
})



//------->End(places/category)

const authorizeUser=(req,res,next)=>{
    const token = req.cookies.token;
    console.log("TOKEN IS ",token);
    if (!token) {
        return res.json({ Error: "Yor are not Authenticated" })
    }
    else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) return res.json({ Error: "Token wrong" })
            const user=decoded;
            req.user=user;
            next();
        })
    }
}
app.post('/pay_detail',authorizeUser, async (req, res) => {
    // console.log("PAY DETAIL I SHERE");
    const model = new mongoose.model('pay_detail', pay_detailSchema);
    req.body.login_id=req.user.id
    // const { name, email, password, image } = req.body;

    if (!req.body.email.length || !req.body.name.length || !req.body.phone.length || !req.body.price.length || !req.body.login_id.length || !req.body.chk_in.length || !req.body.chk_out.length || !req.body.pro_id.length || !req.body.paymentstatus.length) {
        return res.json({ Error: "Please enter details" })
    }

    const data = new model({ email: req.body.email, name: req.body.name, phone: req.body.phone, price: req.body.price, login_id: req.body.login_id, chk_in: req.body.chk_in, chk_out: req.body.chk_out, pro_id: req.body.pro_id, stay_day: req.body.stay_day, paymentstatus: req.body.paymentstatus })
    const result = await data.save();
    return res.json({ Status: "Success" })

})

app.get('/booking_history/:id', async (req, res) => {
    const id = req.params.id;
    const model = new mongoose.model('pay_detail', pay_detailSchema);
    const result = await model.find({ login_id: id });
    res.json({ Result: result, Status: 'Success' })
})

app.get('/findprice/:p', async (req, res) => {
    const p = req.params.p;
    const model = new mongoose.model('pay_detail', pay_detailSchema);
    const result = await model.find({ price: p });
    res.json({ Result: result, Status: 'Success' })
})

app.post('/contact', async (req, res) => {
    var mailOption2 = {
        from: 'u21cs035@coed.svnit.ac.in',
        to: req.body.email,
        subject: req.body.subject,
        text: req.body.message
    }
    if (req.body.name.length == 0 || req.body.email.length == 0 || req.body.subject.length == 0 || req.body.message.length == 0) {
        return res.json({ Error: "Plaese Enter a Data" })
    }
    transporter.sendMail(mailOption2, (err, info) => {
        if (err) return res.json({ Error: "msg send Error in server " });
        // console.log('successfull', info.response)
        return res.json({ Status: "Success" })

    })
})

app.put('/changepassword', async (req, res) => {
    const model = new mongoose.model('signup', signupSchema);
    if (!req.body.oldpassword || !req.body.newpassword || !req.body.confirmpassword) {
        return res.json({ Error: "Please enter password" })
    }
    const chk = await model.find({ password: req.body.oldpassword });
    if (chk.length > 0) {
        if (req.body.newpassword === req.body.confirmpassword) {
            const result = await model.updateOne(
                { password: req.body.oldpassword }, {
                $set: {
                    password: req.body.confirmpassword
                }
            })
            return res.json({ Status: "Success" })
        }
        else {
            return res.json({ Error: "confirm password not matched" })
        }
    }
    else {
        return res.json({ Error: "Invalid Credentials" })
    }
})


// for forget password

app.post('/sendotp', async (req, res) => {
    const model = new mongoose.model('signup', signupSchema);
    if (!req.body.email) {
        return res.json({ Error: "Please enter email" })
    }
    const chk = await model.find({ email: req.body.email });
    if (chk.length > 0) {
        const model1 = new mongoose.model('otp', otpSchema);
        let code = Math.floor((Math.random() * 10000) + 1);
        let otpdata = new model1({
            email: req.body.email,
            otpcode: code,
            expiresIn: new Date().getTime() + 60 * 1000
        })
        const result = await otpdata.save();
        var mailOption = {
            from: 'u21cs035@coed.svnit.ac.in',
            to: req.body.email,
            subject: 'For password reset',
            html: '<p><b>The OTP send successfully via airRv-travel System</b><br/><br/><b>Your password reset OTP is: </b>' + code + '<br/><br/><p>It is valid only for 1 minute!</p></p>'
        }
        transporter.sendMail(mailOption, (err, info) => {
            if (err) return res.json({ Error: "msg send Error in server " });
            // console.log('successfull', info.response)
            return res.json({ Status: "Success" })

        })
    }
    else {
        return res.json({ Error: "Invalid Credentials" })
    }
})

app.post('/forgetpassword/:email', async (req, res) => {
    const email = req.params.email;
    const model1 = new mongoose.model('otp', otpSchema);
    if (!req.body.password || !req.body.confirmpassword || !req.body.code) {
        return res.json({ Error: "Please enter details" })
    }
    const chk = await model1.find({ email: email, otpcode: req.body.code })
    if (chk.length > 0) {
        if (req.body.password === req.body.confirmpassword) {
            let currentTime = new Date().getTime();
            let diff = chk[0].expiresIn - currentTime;
            if (diff > 0) {
                let model2 = new mongoose.model('signup', signupSchema);
                let user = await model2.find({ email: chk[0].email })

                const result = await model2.updateOne(
                    { email: chk[0].email }, {
                    $set: { password: req.body.confirmpassword }
                })

                return res.json({ Status: "Success" })
            }
            else {
                return res.json({ Error: "OTP expired" })
            }
        }
        else {
            return res.json({ Error: "confirm password not matched" })
        }
    }
    else {
        return res.json({ Error: "Invalid OTP" })
    }
})

app.post('/payment', async (req, res) => {
    const model = new mongoose.model('paymenthistory', paymentHistory);

    console.log(req.params.p)

    if (!req.body.cardname.length || !req.body.cardnumber.length || !req.body.expire.length || !req.body.cvv.length || !req.body.Tprice.length) {
        return res.json({ Error: "Please enter details" })
    }

    const data = new model({ cardname: req.body.cardname, cardnumber: req.body.cardnumber, expire: req.body.expire, cvv: req.body.cvv, Tprice: req.body.Tprice })
    const result = await data.save();

    const model1 = new mongoose.model('pay_detail', pay_detailSchema);
    const result1 = await model1.updateOne(
        { price: req.body.Tprice }, {
        $set: { paymentstatus: req.body.paymentstatus }
    })
    return res.json({ Status: "Success" })

})

app.post('/payment/:p', async (req, res) => {
    const model = new mongoose.model('paymenthistory', paymentHistory);

    // console.log(req.params.p)
    const price = req.params.p;

    if (!req.body.cardname.length || !req.body.cardnumber.length || !req.body.expire.length || !req.body.cvv.length || !price.length) {
        return res.json({ Error: "Please enter details" })
    }

    const data = new model({ cardname: req.body.cardname, cardnumber: req.body.cardnumber, expire: req.body.expire, cvv: req.body.cvv, Tprice: price })
    const result = await data.save();

    const model1 = new mongoose.model('pay_detail', pay_detailSchema);
    const result1 = await model1.updateOne(
        { price: price }, {
        $set: { paymentstatus: req.body.paymentstatus }
    })
    return res.json({ Status: "Success" })

})



app.listen(process.env.PORT, () => {
    console.log(`Server is listening on http://localhost:${process.env.PORT}`)
})
