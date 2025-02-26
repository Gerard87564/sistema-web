<?php
    $db_host = "10.0.3.15"; 
    $db_user = "gerard";     
    $db_pass = "educem123*A";
    $db_name = "dvwa";       
    $db_port = 3306;
    $db_socket = "/var/run/mysqld/mysqld.sock"; 

    $db = new mysqli($db_host, $db_user, $db_pass, $db_name, $db_port, $db_socket);

    if ($db->connect_error) {
        die("Conexión fallida: " . $db->connect_error);
    }
    echo "Conexión exitosa a MySQL en $db_host";
?>