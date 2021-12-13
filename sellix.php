<?php

require_once("../classes/connect.php");
require_once("../classes/class.sessions.php");

$payload = file_get_contents('php://input');

$ses = new Users();

$secret = "Mw4EKfuCewqtaEksE60qQgxJyI8xh02X"; // replace with your webhook secret
$header_signature = $_SERVER["HTTP_X_SELLIX_SIGNATURE"];
$signature = (string) hash_hmac('sha512', $payload, $secret);

if(hash_equals($signature, $header_signature)) {
    $arr = json_decode($payload, true);
    
    $ses_id = $arr["data"]["custom_fields"]["ses_id"];
    $username = $ses->username($pdo, $ses_id);
    $email = $arr["data"]["customer_email"];
    $price = $arr["data"]["total"];
    $date = $arr["data"]["created_at"];
    $currency = $arr["data"]["currency"];
    $status = $arr["event"];
    
    if($status == "order:paid") {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM transactions WHERE date=:date AND username=:username");
        $stmt->bindParam(":date", $date, PDO::PARAM_INT);
        $stmt->bindParam(":username", $username, PDO::PARAM_STR);
        if($stmt->execute() && $stmt->fetchColumn() != 0) {
            return;
        }
        
        $stmt = $pdo->prepare("INSERT INTO `transactions`(`email`, `username`, `date`, `status`, `currency`, `price`) VALUES (:email, :username, :date, :status, :currency, :price)");
        $stmt->bindParam(":email", $email, PDO::PARAM_STR);
        $stmt->bindParam(":date", $date, PDO::PARAM_STR);
        $stmt->bindParam(":status", $status, PDO::PARAM_STR);
        $stmt->bindParam(":currency", $currency, PDO::PARAM_STR);
        $stmt->bindParam(":price", $price, PDO::PARAM_STR);
        $stmt->bindParam(":username", $username, PDO::PARAM_STR);
        
        if($stmt->execute()) {
            $nb = $userInf['solde'] + $price;
            $stmt = $pdo->prepare("UPDATE `users` SET `solde`=:balance WHERE id=:ses_id");
            $stmt->bindParam(":ses_id", $ses_id, PDO::PARAM_INT);
            $stmt->bindParam(":balance", $nb, PDO::PARAM_INT);
        
            $stmt->execute();
        }
    }
}