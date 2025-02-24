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
            echo "
            <!DOCTYPE html>
            <html lang='es'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Resultat</title>
                <style>
                    body {
                        font-family: 'Arial', sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        color: #333;
                    }
                    .container {
                        text-align: center;
                        padding: 20px;
                        background-color: #ffffff;
                        border-radius: 10px;
                        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                        max-width: 600px;
                        width: 100%;
                    }
                    .correct-flag {
                        color: green;
                        font-weight: bold;
                        font-size: 22px;
                        background-color: #d4edda;
                        padding: 15px;
                        border-radius: 8px;
                        border: 1px solid #c3e6cb;
                        margin: 20px 0;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <p class='correct-flag'>¡Flag correcta!</p>
                </div>
            </body>
            </html>
            ";
        } else {
            echo "
            <!DOCTYPE html>
            <html lang='es'>
            <head>
                <meta charset='UTF-8'>
                <meta name='viewport' content='width=device-width, initial-scale=1.0'>
                <title>Resultat</title>
                <style>
                    body {
                        font-family: 'Arial', sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f9;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        color: #333;
                    }
                    .container {
                        text-align: center;
                        padding: 20px;
                        background-color: #ffffff;
                        border-radius: 10px;
                        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                        max-width: 600px;
                        width: 100%;
                    }
                    .incorrect-flag {
                        color: red;
                        font-weight: bold;
                        font-size: 22px;
                        background-color: #f8d7da;
                        padding: 15px;
                        border-radius: 8px;
                        border: 1px solid #f5c6cb;
                        margin: 20px 0;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    }
                </style>
            </head>
            <body>
                <div class='container'>
                    <p class='incorrect-flag'>¡Flag incorrecta!</p>
                </div>
            </body>
            </html>
            ";
        }
    } else {
        echo "<p style='color: red;'>No se recibió ninguna flag.</p>";
    }

    ftp_close($conn_id);
?>