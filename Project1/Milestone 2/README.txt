Team members: Hung Tran, Megan Kanne

Because I create a fake group key stored in the key database to test the password generated key, the fake group name is "test_string" and group 
key is "correct_password". That's why when creating group, user can't name the group "test_string". Otherwises, the password to key database will not work the next time that the user login to his/her account

When a user login using the extension for the first time, a prompt message will appear asking for creating a password to the key database. After that, every new session, the user will be asked to enter his/her password. If the password is correct, an alert message "Correct Password" will appear. Otherwises, if the alert message doesn't show up, the password is incorrect

After creating a group, the user needs to go to settings to generate a new key for the group. 