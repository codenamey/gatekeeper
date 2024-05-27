import mysql from 'mysql2/promise';
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { exec } from 'child_process';

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

const getOptions = (bearer, type, customer) => {
    let options;
    if(type.includes('get')) {
        options = {
            method: 'GET',
            headers: {
                'Authorization': bearer,
                'Content-Type': 'application/json'
            }
        };
    } else {
        options = {
            method: 'POST',
            headers: {
                'Authorization': bearer,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(customer)
        };
    }
    return options;
};

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.post('/test', async (req, res) => {
    const body = req.body;
    console.log({body});
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
            addIPAddress(ip);
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

const allowedipaddress = [];

const addIPAddress = (ip) => {
    const timestamp = new Date();
    allowedipaddress.push({ ip, timestamp });
    console.log(`Added IP address ${ip} at ${timestamp}`);

    // Add the IP address to iptables
    exec(`sudo iptables -I INPUT -s ${ip} -j ACCEPT`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error adding IP address to iptables: ${error.message}`);
            return;
        }
        if (stderr) {
            console.error(`iptables stderr: ${stderr}`);
            return;
        }
        console.log(`iptables stdout: ${stdout}`);
    });
};

const removeExpiredIPAddresses = () => {
    const now = new Date();
    allowedipaddress.forEach((entry, index) => {
        const timeDiff = (now - new Date(entry.timestamp)) / 1000 / 60; // Difference in minutes
        if (timeDiff > 60) { // If more than 1 hour
            console.log(`Removing expired IP address ${entry.ip}`);

            // Remove the IP address from iptables
            exec(`sudo iptables -D INPUT -s ${entry.ip} -j ACCEPT`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Error removing IP address from iptables: ${error.message}`);
                    return;
                }
                if (stderr) {
                    console.error(`iptables stderr: ${stderr}`);
                    return;
                }
                console.log(`iptables stdout: ${stdout}`);
            });

            allowedipaddress.splice(index, 1);
        }
    });
};

// Check and remove expired IP addresses every minute
setInterval(removeExpiredIPAddresses, 60 * 1000);


const server = app.listen(port, () => console.log(`Server is running:  ${port}!`));
console.log('Server started with variables:');
console.log({env})
console.log('process.env.emailbearer', process.env.emailbearer);
export default server;
