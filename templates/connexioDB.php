<?php
    $db_host = "10.0.5.210"; 
    $db_user = "dvwa";     
    $db_pass = "p@ssw0rd"; 
    $db_name = "dvwa";       
    $db_port = 3306;

    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port);

    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }
    echo "Conexión exitosa a MySQL en $db_host";
?>