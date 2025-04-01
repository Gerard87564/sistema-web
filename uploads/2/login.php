<?php
    session_start();

    require_once('../PHP/connexioDB.php');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if(isset($_POST['nomU'])) {
            $usuari = $_POST['nomU'];
        }
        
        if (isset($_POST['email'])) {
            $usuari = $_POST['email'];
        }
        
        $contrasenya = $_POST['passwd'];

        if ($_SESSION['nomU'] == $usuari && $_SESSION['passwd'] == $contrasenya ||
        $_SESSION['mail'] == $usuari && $_SESSION['passwd'] == $contrasenya) {    
            header('Location: ../HTML/perfil.html');
        } else {
            echo 'Credencials incorrectes';
        }
    } 
?>