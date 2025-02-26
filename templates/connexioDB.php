<?php
    $db_host = "10.0.3.15"; 
    $db_user = "gerard";     
    $db_pass = "educem123*A";
    $db_name = "dvwa";       
    $db_port = 3306;
    $db_socket = "/var/run/mysqld/mysqld.sock"; 

    $conn = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port, $db_socket);

    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }
    echo "Conexión exitosa a MySQL en $db_host";
?>