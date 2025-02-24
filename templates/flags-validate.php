<?php
    $ftp_server = "10.0.5.210"; 
    $ftp_user_name = "scruz";  
    $ftp_user_pass = "1234";  
    $ftp_directory = "/srv/ftp"; 

    $conn_id = ftp_connect($ftp_server);
    if (!$conn_id) {
        die("No se pudo conectar al servidor FTP $ftp_server");
    }

    $login_result = ftp_login($conn_id, $ftp_user_name, $ftp_user_pass);
    if (!$login_result) {
        die("Conexión FTP fallida");
    }

    if (isset($_GET['flag'])) {
        $flag = $_GET['flag']; 

        ftp_chdir($conn_id, $ftp_directory);
        $file_list = ftp_nlist($conn_id, ".");

        if (in_array($flag, $file_list)) {
            echo "<p style='color: green;'>¡Flag correcta!</p>";
        } else {
            echo "<p style='color: red;'>Flag incorrecta. Inténtalo de nuevo.</p>";
        }
    } else {
        echo "<p style='color: red;'>No se recibió ninguna flag.</p>";
    }

    ftp_close($conn_id);
?>