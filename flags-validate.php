<?php
$conn_db = new mysqli("localhost", "root", "", "ctf_challenges");
if ($conn_db->connect_error) {
    die("Conexión a la base de datos fallida: " . $conn_db->connect_error);
}

$ftp_server = "10.0.4.52";
$ftp_user_name = "usuario";
$ftp_user_pass = "contraseña";

$conn_id = ftp_connect($ftp_server);
if (!$conn_id) {
    die("No se pudo conectar al servidor FTP $ftp_server");
}

$login_result = ftp_login($conn_id, $ftp_user_name, $ftp_user_pass);
if (!$login_result) {
    die("Conexión FTP fallida");
}

if (isset($_POST['directory']) && isset($_POST['flag'])) {
    $directory = $_POST['directory'];
    $flag = $_POST['flag'];

    // Verificar si el directorio existe antes de cambiarlo
    $dir_list = ftp_nlist($conn_id, ".");
    if (!in_array($directory, $dir_list)) {
        die("El directorio '$directory' no existe en el servidor FTP.<br>");
    }

    if (ftp_chdir($conn_id, $directory)) {
        echo "Has cambiado al directorio: $directory <br>";

        $file_list = ftp_nlist($conn_id, ".");
        echo "Archivos en $directory:<br><ul>";
        foreach ($file_list as $file) {
            echo "<li>" . htmlspecialchars($file) . "</li>";
        }
        echo "</ul>";

        // Consulta segura contra inyección SQL
        $stmt = $conn_db->prepare("SELECT * FROM flags WHERE flag = ?");
        $stmt->bind_param("s", $flag);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            echo "¡Flag correcta!<br>";
        } else {
            echo "Flag incorrecta. Intenta otro intento.<br>";
        }

        $stmt->close();
    } else {
        echo "No se puede cambiar al directorio: $directory<br>";
    }
} else {
    echo "Faltan datos en la solicitud.";
}

ftp_close($conn_id);
$conn_db->close();
?>