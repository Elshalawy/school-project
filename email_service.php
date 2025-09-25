<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

class EmailService {
    private $mailer;
    public function __construct() {
        $this->mailer = new PHPMailer(true);
        // Configure SMTP or your preferred email settings
        $this->mailer->isSMTP();
        $this->mailer->Host = 'smtp.gmail.com';
        $this->mailer->SMTPAuth = true;
        $this->mailer->Username = 'elwork444@gmail.com';
        $this->mailer->Password = 'wzemkzjxpnxryrei';
        $this->mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $this->mailer->Port = 587;
    }
    
    public function sendPasswordResetEmail($email, $name, $resetToken) {
        try {
            $resetLink = "http://localhost/school-web/reset_password.php?token=" . $resetToken;
            
            $this->mailer->setFrom('elwork444@gmail.com', 'School Portal');
            $this->mailer->addAddress($email, $name);
            $this->mailer->isHTML(true);
            $this->mailer->Subject = 'Password Reset Request';
            $this->mailer->Body = "
                <h2>Password Reset Request</h2>
                <p>Dear {$name},</p>
                <p>We received a request to reset your password. Click the link below to set a new password:</p>
                <p><a href='{$resetLink}'>{$resetLink}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>Best regards,<br>School Portal Team</p>
            ";
            
            $this->mailer->send();
            return true;
        } catch (Exception $e) {
            error_log("Email sending failed: " . $e->getMessage());
            return false;
        }
    }
}
?>
