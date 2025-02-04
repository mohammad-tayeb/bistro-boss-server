const express = require('express');
const app = express();
const cors = require('cors');
const port = process.env.PORT || 5000
require('dotenv').config()
const jwt = require('jsonwebtoken');

//*************************************************** */ stripe
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);


//middleware
app.use(cors());
app.use(express.json())


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.z0jqk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});
async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        const menuCollection = client.db("bistroDB").collection("menu")
        const reviewsCollection = client.db("bistroDB").collection("reviews")
        const cartCollection = client.db("bistroDB").collection("carts")
        const usersCollection = client.db("bistroDB").collection("users")
        const paymentsCollection = client.db("bistroDB").collection("payments")

        //middleware 
        //verify token
        //This code defines a middleware function (verifyToken) that is used to verify the JWT token in incoming requests. It ensures that the user is authenticated before allowing access to protected routes.
        const verifyToken = (req, res, next) => {
            if (!req.headers.authorization) { //authorization data is send from axiosSecure after getting the token from local storage
                return res.status(401).send({ message: 'unauthorized access' })
            }
            const token = req.headers.authorization.split(' ')[1] //token data theke 'Bearer' bad diye just token data nibe
            //jwt token verify buldin process 
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
                if (err) {
                    return res.status(401).send({ message: 'forbidden access' })
                }
                req.decoded = decoded;
                next() //continue to whatever next/verifyToken -> verifyAdmin,
            })
        }

        //use verifyAdmin after verifyToken
        const verifyAdmin = async (req, res, next) => {
            //AuthProvider theke '/jwt' route call korar somoy 'userInfo' patano hoice
            //jeta decoder e store kora ache token verify korar por
            const email = req.decoded.email
            const query = { email: email }
            const user = await usersCollection.findOne(query)
            const isAdmin = user?.role === 'admin'
            if (!isAdmin) {
                return res.status(403).send({ message: 'forbidden access' })
            }
            next()
        }

        //*********************************jwt related api
        // This code is an route that generates a JWT (JSON Web Token) for authentication.
        // generate token which can be accessed by frontend using a route
        // *********************** 1 token generate ****************
        app.post('/jwt', async (req, res) => {
            const user = req.body
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
                expiresIn: '1h'
            })
            res.send({ token })
        })


        ////////////////////////////////////////// user related api
        app.get('/users', verifyToken, verifyAdmin, async (req, res) => {  //********use verifyToken middleware
            const result = await usersCollection.find().toArray();
            res.send(result)
        })
        app.post('/users', async (req, res) => {
            const user = req.body;
            // check if the user already exists/if does not exist then save the uer info in database
            const query = { email: user.email } // query to check DB for recived user email from req.body
            const existingUser = await usersCollection.findOne(query) //if user email exist then store it in existingUser
            if (existingUser) {
                return res.send({ message: 'user already exists', insertedId: null })
            }

            const result = await usersCollection.insertOne(user)
            res.send(result)
        })
        //delete user
        app.delete('/users/:id', verifyAdmin, verifyToken, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await usersCollection.deleteOne(query)
            res.send(result)
        })
        //add admin
        app.patch('/users/admin/:id', verifyAdmin, verifyToken, async (req, res) => {
            const id = req.params.id
            const filter = { _id: new ObjectId(id) }
            const updatedDoc = {
                $set: {
                    role: 'admin'
                }
            }
            const result = await usersCollection.updateOne(filter, updatedDoc)
            res.send(result)
        })
        //admin kina check kore admin er role er data er sathe milabe mile gele data patabe
        app.get('/users/admin/:email', verifyToken, async (req, res) => {
            const email = req.params.email //email AuthProvider er useEffect theke patano hoice
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: 'unauthorized access' })
            }
            const query = { email: email }
            const user = await usersCollection.findOne(query)
            let admin = false
            if (user) {
                admin = user?.role === 'admin'
            }
            res.send({ admin })
        })


        //////////////////////////////menu related api
        //get single menu data
        app.get('/menu/:id', async (req, res) => {
            const id = req.params.id
            const query = { _id: new ObjectId(id) }
            const result = await menuCollection.findOne(query)
            res.send(result)
        })
        //update menu item
        app.patch('/menu/:id', async (req, res) => {
            const item = req.body
            const id = req.params.id
            const filter = { _id: new ObjectId(id) }
            const updatedDoc = {
                $set: {
                    name: item.name,
                    category: item.category,
                    price: item.price,
                    details: item.details,
                    recipe: item.recipe,
                    image: item.image
                }
            }
            const result = await menuCollection.updateOne(filter, updatedDoc)
            res.send(result)
        })
        //delete menuItem
        app.delete('/menu/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await menuCollection.deleteOne(query)
            res.send(result)
        })
        app.post('/menu', verifyToken, verifyAdmin, async (req, res) => {
            const item = req.body;
            const result = await menuCollection.insertOne(item)
            res.send(result)
        })
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray()
            res.send(result)
        })
        app.get('/reviews', async (req, res) => {
            const result = await reviewsCollection.find().toArray()
            res.send(result)
        })

        //////////////////////////////////////////carts related route
        app.get('/carts', async (req, res) => {
            const email = req.query.email  //changes
            const query = { email: email }   //changes
            const result = await cartCollection.find(query).toArray();
            res.send(result)
        })

        app.post('/carts', async (req, res) => {
            const cartItem = req.body;
            const result = await cartCollection.insertOne(cartItem);
            res.send(result)
        })

        app.delete('/carts/:id', async (req, res) => {
            const id = req.params.id
            const query = { _id: new ObjectId(id) }
            const result = await cartCollection.deleteOne(query)
            res.send(result);
        })



        //////////////////////////////////////stripe related routes
        //payment intent
        app.post('/create-payment-intent', async (req, res) => {
            const { price } = req.body;
            const amount = parseInt(price * 100) //stripe poisha te price hisba kore 1taka/100 poisa

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            })

            res.send({
                clientSecret: paymentIntent.client_secret,
            });
        })

        // payment information storeing and also deleting cart data after payment
        app.post('/payments', async (req, res) => {
            //insert payment data
            const payment = req.body
            const paymentResult = await paymentsCollection.insertOne(payment)
            console.log(payment)
            // delete cart data
            //here 'payemnt.cartIds' is an array. all the including ids in the array are deleted  
            const query = {
                _id: {
                    $in: payment.cartIds.map(id => new ObjectId(String(id)))
                }
            }
            const deleteResult = await cartCollection.deleteMany(query);
            res.send({ paymentResult, deleteResult })

        })

        //*******************************************payment information receiving
        app.get('/payments/:email', verifyToken, async (req, res) => {
            const query = { email: req.params.email }
            if (req.params.email !== req.decoded.email) {
                return res.status(403).send({ message: 'forbidden access' })
            }
            const result = await paymentsCollection.find(query).toArray()
            res.send(result)
        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('boss is not working/sitting')
})

app.listen(port, () => {
    console.log(`Bistro Boss Server is running on port: ${port}`)
})