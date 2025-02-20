<?php
$conn_db = new mysqli("localhost", "root", "", "ctf_challenges");
if ($conn_db->connect_error) {
    die("Conexió a la base de dades fallida: " . $conn_db->connect_error);
}

$ftp_server = "ftp://10.0.4.52";
$ftp_user_name = "usuario";
$ftp_user_pass = "contraseña";  

$conn_id = ftp_connect($ftp_server) or die("No se pudo conectar a $ftp_server");

$login_result = ftp_login($conn_id, $ftp_user_name, $ftp_user_pass);
if (!$login_result) {
    echo "Conexió FTP fallida";
    exit;
}

if (isset($_POST['directory']) && isset($_POST['flag'])) {
    $directory = $_POST['directory'];
    $flag = $_POST['flag'];

    if (ftp_chdir($conn_id, $directory)) {
        echo "Has cambiat al directori: $directory <br>";

        $file_list = ftp_nlist($conn_id, ".");
        echo "Archius en $directory:<br>";
        echo "<ul>";
        foreach ($file_list as $file) {
            echo "<li>" . htmlspecialchars($file) . "</li>";
        }
        echo "</ul>";

        $query = "SELECT * FROM flags WHERE flag='$flag'";
        $result = $conn_db->query($query);

        if ($result->num_rows > 0) {
            echo "¡Flag correcte!<br>";
        } else {
            echo "Flag incorrecte. Intenta un altre cop.<br>";
        }
    } else {
        echo "No es pot cambiar el directori: $directory<br>";
    }
} else {
    header('Location: templates/sqli-game.html');
}

ftp_close($conn_id);
$conn_db->close();
?>