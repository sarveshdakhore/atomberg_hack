export const hero_home = (req,res)=>{
  res.send('hero home Page');
}

export const data = (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Home Page</title>
    </head>
    <body>
      <h1>Welcome to the Home Page</h1>
      <p>This is a sample HTML response.</p>
    </body>
    </html>
  `);
}