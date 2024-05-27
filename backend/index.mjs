
import  mysql  from 'mysql2/promise';
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';

let env = process.env;
  
   // Create a connection to the database
const connection = await mysql.createConnection({
    host: env.DBHOST,
    user: env.DBUSER,
    password: env.DBPASSWORD,
    database: env.DBDATABASE
});

const genarateToken = (email, ipaddress) => {
    const payload = {
        email: email,
        ipaddress: ipaddress
      };
    
    const generatedToken = jwt.sign(
        payload,
        env.jwtSecret,
        { expiresIn: '24H' }
      );
      return generatedToken; 
}

const checkEmailAccess = async (email) => {
    try {
        const [results] = await connection.execute(
            `SELECT * FROM mail_user WHERE email = ?`,
            [email]
        );

        if (results.length === 0) {
            return "not allowed";
        } else {
            return "EMAIL:" + results[0].email;
        }
    } catch (error) {
        return "error: " + error.message;
    }
}
const app = express();
const port = 3000;
const getOptions = (bearer, GET)=>{
    let options;
    if(type.includes('get')) {
      options = {
        method: 'GET',
        headers: {
          'Authorization': bearer,
          'Content-Type': 'application/json'
        }
      };
    }
    else {
      options = {
        method: 'POST',
        headers: {
          'Authorization': bearer,
          'Content-Type': 'application/json'
        },
        body: customer
      };
  
    }
    return options;
  };

  const options = {
    method: 'GET',
    headers: {
      'Authorization': env.bearer,
      'Content-Type': 'application/json'
    },
    body: 'false'
  };
  app.use(cors());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());
  
  app.post('/test', async (req, res) => {
    const body = req.body;
      console.log({body})
      res.send('OK');
  });

  app.post('/verifytoken', async (req, res) => {
    const {email, token} = req.body;
    jwt.verify(token, env.jwtSecret, (err, decoded) => {
        if (err) {
            console.log(err);
            res.send('token is not valid');
        } else {
            console.log(decoded);
            const ip = decoded.ipaddress.split(':').pop(); 
            console.log({ip});
            res.send('token is valid');
        }
    });
});

  app.post('/grantaccesstoken', async (req, res) => {
    const remoteip = req.headers['x-forwarded-for'] || req.socket.remoteAddress 
    const body = req.body;
      const {email, url} = body;
      const result = await checkEmailAccess(email);
      if(result.includes('not allowed')){
        res.send("email is not allowed")
      } else {
        const token = genarateToken(email, remoteip);
        console.log({token});
        res.send(result);
  
      }

  });

const server = app.listen(port, () => console.log(`Server is running:  ${port}!`));
console.log('Server started with variables:');
console.log({env})
console.log('process.env.emailbearer', process.env.emailbearer);
export default server;
