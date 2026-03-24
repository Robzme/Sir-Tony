<?php
require_once "conn.php"
// Encryption helpers
function _uylogres_encryption_key(): string {
    return hash('sha256', 'uylogres_secret_key_2026', true);
}

function _uylogres_encryption_iv(): string {
    // 16 bytes for AES-256-CBC
    return substr(hash('sha256', 'uylogres_secret_iv_2026'), 0, 16);
}

function encrypt_value(string $plaintext): string {
    return openssl_encrypt($plaintext, 'AES-256-CBC', _uylogres_encryption_key(), 0, _uylogres_encryption_iv());
}

function decrypt_value(string $ciphertext): string {
    $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', _uylogres_encryption_key(), 0, _uylogres_encryption_iv());
    return $decrypted === false ? '' : $decrypted;
}

//Registration processing
if($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["register"])){
    $user = isset($_POST["username"]) ? htmlspecialchars($_POST["username"]) : null;
    $email = isset($_POST["email"]) ? htmlspecialchars($_POST["email"]) : null;
    $pass = isset($_POST["password"]) ? htmlspecialchars($_POST["password"]) : null;

    if (!$user || !$email || !$pass) {
        die("Error, missing required fields. <a href='reg.php'>Go back</a>");
    }

    $encryptedUsername = encrypt_value($user);
    $encryptedEmail = encrypt_value($email);

    try{
        $checkSQL = "SELECT username, email FROM accounts WHERE username = :username OR email = :email";
        $checkstat = $pdo->prepare($checkSQL);
        $checkstat->execute(['username' => $encryptedUsername, 'email' => $encryptedEmail]);
        $existingUser = $checkstat->fetch(PDO::FETCH_ASSOC);

        if($existingUser){
            if(decrypt_value($existingUser['username']) === $user){
                die("Username already exists. <a href='reg.php'>Go back</a>");
            }
            if(decrypt_value($existingUser['email']) === $email){
                die("Email already exists. <a href='reg.php'>Go back</a>");
            }
        }
        //Database Security Using PDO prepare
        $hashedPassword = password_hash($pass, PASSWORD_DEFAULT);

        $insertSQL = "INSERT INTO accounts (username, email, password) VALUES (:username, :email, :password)";
        $insertStat = $pdo->prepare($insertSQL);
        $insertStat->execute([
            'username' => $encryptedUsername,
            'email' => $encryptedEmail,
            'password' => $hashedPassword
          ]);

        echo "Registration successful. <a href='log.php'>Login here</a>";
    } catch (PDOException $e) {
        die("Error: " . $e->getMessage());
    }
};
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration</title>
</head>
<body>
    <form action="process.php" method="POST" onsubmit="return validatePassword()">
        <input type="text" name="username" placeholder="username" required>
        <br>
        <input type="text" name="email" placeholder="email" required>
        <br>
        <input type="password" id="password" name="password" placeholder="password" required>
        <br>
        <div id="passwordError" style="color: red;"></div>
        <input type="hidden" name="register" value="2">
        <input type="submit" value="Register">
    </form>
    <br>
    <a href="log.php">Already have an account? Login here</a>
    <script>
        function validatePassword() {
            const password = document.getElementById('password').value;
            const errorElement = document.getElementById('passwordError');
            
            // Clear previous error
            errorElement.textContent = '';
            
            // Check minimum length
            if (password.length < 8) {
                errorElement.textContent = 'Password must be at least 8 characters long.';
                return false;
            }
            
            // Check for letters and numbers
            const hasLetter = /[a-zA-Z]/.test(password);
            const hasNumber = /\d/.test(password);
            if (!hasLetter || !hasNumber) {
                errorElement.textContent = 'Password must contain both letters and numbers.';
                return false;
            }
            
            // Check for special characters
            const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
            if (!hasSpecialChar) {
                errorElement.textContent = 'Password must contain at least one special character.';
                return false;
            }
            
            return true;
        }
    </script>
</body>
</html>
