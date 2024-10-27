const userPasswordEmailTemplate = (password) => {
    return `
        <div style="font-family: Arial, sans-serif; font-size: 16px; color: #333;">
            <h2 style="color: #4CAF50;">Dashboard Access Password</h2>
            <p>Dear User,</p>
            <p>Your new login password for accessing the dashboard has been generated.</p>
            <p><strong>Password:</strong> <span style="font-size: 18px; color: #333;">${password}</span></p>

               <br><br>
            <b>Please make sure this password is for one time use only.</b>
           
           
          
            <br><br>
            <p>Thank you!</p>
            <p><strong>The Admin Team</strong></p>
        </div>
    `;
};

module.exports = userPasswordEmailTemplate;