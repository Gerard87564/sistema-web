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

    if (isset($_GET['flag']) && isset($_GET['file'])) {
        $flag = $_GET['flag'];
        $file = $_GET['file'];

        ftp_chdir($conn_id, $ftp_directory);
        $file_list = ftp_nlist($conn_id, ".");

        // Asegurar que el archivo existe antes de leerlo
        if (in_array($file, $file_list)) {
            $temp_file = "temp_$file";
            if (ftp_get($conn_id, $temp_file, $file, FTP_BINARY)) {
                $content = file_get_contents($temp_file);
                unlink($temp_file); // Elimina el archivo temporal después de leerlo
            } else {
                die("Error al descargar el archivo desde el FTP.");
            }
        } else {
            die("El archivo no existe en el servidor FTP.");
        }

        if (in_array($flag, $file_list)) {
            if (trim($content) == trim($flag)) {
                $message = "¡Flag correcta!";
                $class = "correct-flag";
                $bg_color = "#d4edda"; // Verde claro
            } else {
                $message = "¡Flag incorrecta!";
                $class = "incorrect-flag";
                $bg_color = "#f8d7da"; // Rojo claro
            }
        } else {
            $message = "Archivo incorrecto...";
            $class = "incorrect-flag";
            $bg_color = "#f8d7da"; // Rojo claro
        }

        echo "
        <!DOCTYPE html>
        <html lang='es'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Resultado</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background: linear-gradient(45deg, #dc3545, #000000);
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
                .{$class} {
                    color: black;
                    font-weight: bold;
                    font-size: 22px;
                    background-color: {$bg_color};
                    padding: 15px;
                    border-radius: 8px;
                    margin: 20px 0;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }
            </style>
        </head>
        <body>
            <div class='container'>
                <p class='{$class}'>{$message}</p>
            </div>
        </body>
        </html>
        ";
    } else {
        echo "<p style='color: red;'>No se recibió ninguna flag o archivo.</p>";
    }

    ftp_close($conn_id);
?>