<?php

require_once("config.php");

session_start();

$errors = [];

// SRP6 Calculation Functions
function CalculateSRP6Verifier($username, $password, $salt)
{
    // algorithm: v = g^h2 (mod N)
    $g = 7;
    $N = gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);

    // h1 = SHA1("USERNAME:PASSWORD")
    $h1 = sha1(strtoupper($username) . ':' . strtoupper($password), TRUE);

    // h2 = SHA1(salt + h1)
    $h2 = sha1($salt . $h1, TRUE);

    // Convert h2 to integer (little-endian)
    $h2 = gmp_import($h2, 1, GMP_LSW_FIRST);

    // v = g^h2 mod N
    $v = gmp_powm($g, $h2, $N);

    // Convert v back to binary (little-endian, 32 bytes)
    $verifier = gmp_export($v, 1, GMP_LSW_FIRST);
    $verifier = str_pad($verifier, 32, chr(0), STR_PAD_RIGHT);

    return $verifier;
}

if (!empty($_POST["accountname"]) && !empty($_POST["password"]) && !empty($_POST["password2"])) {

    $mysql_connect = mysqli_connect($mysql["host"], $mysql["username"], $mysql["password"], $mysql["realmd"]) or die("Нет подключений к базе.");

    $post_accountname = trim(strtoupper($_POST["accountname"]));
    $post_password = trim(strtoupper($_POST["password"]));
    $post_password2 = trim(strtoupper($_POST["password2"]));

    // Default values for removed fields
    $post_email = "";
    $post_expansion = 2; // Default to WotLK

    // Security: Prepared Statement for check
    $stmt = mysqli_prepare($mysql_connect, "SELECT COUNT(*) FROM account WHERE username = ?");
    mysqli_stmt_bind_param($stmt, "s", $post_accountname);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $count);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    if ($count != 0) {
        $errors[] = "Запрашиваемое имя учетной записи уже используется. Пожалуйста, попробуйте другой логин.";
    }

    if (strlen($post_accountname) < 3) {
        $errors[] = "Запрашиваемое имя пользователя слишком короткое. Пожалуйста, попробуйте использовать больше букв.";
    }
    if (strlen($post_accountname) > 32) {
        $errors[] = "Запрашиваемое имя учетной записи слишком длинное. Пожалуйста, попробуйте использовать меньше букв.";
    }
    if (strlen($post_password) < 6) {
        $errors[] = "Запрошенный пароль слишком короткий. Пожалуйста, попробуйте снова.";
    }
    if (strlen($post_password) > 32) {
        $errors[] = "Запрошенный пароль длинный. Пожалуйста, попробуйте снова.";
    }
    // Fixed: ereg -> preg_match
    if (!preg_match("/^[0-9a-zA-Z]+$/", $post_accountname)) {
        $errors[] = "Ваше имя пользователя может содержать только буквы или цифры. Пожалуйста, попробуйте снова.";
    }
    if (!preg_match("/^[0-9a-zA-Z]+$/", $post_password)) {
        $errors[] = "Ваш пароль может содержать только буквы или цифры. Пожалуйста, попробуйте снова.";
    }

    if ($post_accountname == $post_password) {
        $errors[] = "Пароли не совпадают. Пожалуйста, попробуйте снова.";
    }
    if ($post_password != $post_password2) {
        $errors[] = "Пароли не совпадают. Пожалуйста, попробуйте снова.";
    }

    if (empty($errors)) {
        // SRP6 Generation
        $salt = random_bytes(32);
        $verifier = CalculateSRP6Verifier($post_accountname, $post_password, $salt);

        // Insert new account
        $stmt = mysqli_prepare($mysql_connect, "INSERT INTO account (username, salt, verifier, email, last_ip, expansion) VALUES (?, ?, ?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, "sssssi", $post_accountname, $salt, $verifier, $post_email, $_SERVER["REMOTE_ADDR"], $post_expansion);

        if (mysqli_stmt_execute($stmt)) {
            $errors[] = 'Вы успешно создали учетную запись: <font color="yellow">' . htmlspecialchars($post_accountname) . '</font>.';
        } else {
            $errors[] = "Error: " . mysqli_error($mysql_connect);
        }
        mysqli_stmt_close($stmt);
    }
    mysqli_close($mysql_connect);
}

function error_msg()
{
    global $errors;
    if (!empty($errors)) {
        foreach ($errors as $msg) {
            echo '<div class="errors">' . $msg . '</div>';
        }
    }
}

?>

<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="site.css" />
    <meta name="description" content="<?php echo $site["meta_description"] ?>" />
    <meta name="keywords" content="<?php echo $site["meta_keywords"]; ?>" />
    <meta name="robots" content="<?php echo $site["meta_robots"] ?>" />
    <meta name="author" content="Jordy Thery" />
    <link rel="shortcut icon" href="img/favicon.png" type="image/png" />
    <title><?php echo $site["title"]; ?></title>
</head>

<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="site.css" />
    <meta name="description" content="<?php echo $site["meta_description"] ?>" />
    <meta name="keywords" content="<?php echo $site["meta_keywords"]; ?>" />
    <meta name="robots" content="<?php echo $site["meta_robots"] ?>" />
    <meta name="author" content="Jordy Thery" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="shortcut icon" href="img/favicon.png" type="image/png" />
    <title><?php echo $site["title"]; ?></title>
</head>

<body>

    <script type="text/javascript">
        function checkform(form) {
            if (form.accountname.value == "") {
                alert("Вы не заполнили имя Вашей учетной записи. Пожалуйста, попробуйте снова.");
                form.accountname.focus();
                return false;
            } else {
                if (form.accountname.value.length < 3) {
                    alert("Имя пользователя слишком короткое!");
                    form.accountname.focus();
                    return false;
                }
            }
            if (form.password.value == "") {
                alert("Вы не заполнили пароль. Пожалуйста, попробуйте снова.");
                form.password.focus();
                return false;
            } else {
                if (form.password.value.length < 6) {
                    alert("Пароль слишком короткий!");
                    form.password.focus();
                    return false;
                }
            }
            if (form.password2.value == "") {
                alert("Вы не заполнили пароль. Пожалуйста, попробуйте снова.");
                form.password2.focus();
                return false;
            }
            if (form.password.value == form.accountname.value) {
                alert("Пароль не должен совпадать с логином. Пожалуйста, попробуйте снова.");
                form.password.focus();
                return false;
            }
            if (form.password.value != form.password2.value) {
                alert("Пароли не совпадают. Пожалуйста, попробуйте снова.");
                form.password.focus();
                return false;
            }
            return true;
        }
    </script>

    <div class="main-container">
        <div class="register-box">
            <a href="<?php echo $_SERVER["PHP_SELF"]; ?>">
                <img src="img/logo.png" alt="<?php echo $site["title"]; ?>" />
            </a>

            <?php error_msg(); ?>

            <form action="<?php echo $_SERVER["PHP_SELF"]; ?>" method="POST" onsubmit="return checkform(this);"
                name="reg">

                <table class="form">
                    <tr>
                        <td align="left">
                            Логин<br>
                            <input name="accountname" type="text" maxlength="32" placeholder="Логин" />
                        </td>
                    </tr>
                    <tr>
                        <td align="left">
                            Пароль<br>
                            <input name="password" type="password" maxlength="32" placeholder="Пароль" />
                        </td>
                    </tr>
                    <tr>
                        <td align="left">
                            Повторите пароль<br>
                            <input name="password2" type="password" maxlength="32" placeholder="Повторите пароль" />
                        </td>
                    </tr>
                    <tr>
                        <td align="center">
                            <input type="submit" class="sbm" value="Регистрация" />
                        </td>
                    </tr>
                </table>

            </form>

            <div class="copy"><b><?php echo $site["realmlist"]; ?></b><br /></div>

            <?php
            // Using file_exists before include to prevent fatal errors
            if (file_exists('./modulec_bx/obschiy.php')) {
                echo '<div class="copy"><b><font color=#7FFF00>Общий онлайн :</font>';
                include('./modulec_bx/obschiy.php');
                echo '</b><br /></div>';
            }
            if (file_exists('./modulec_bx/uptime_lk.php')) {
                echo '<div class="copy"><b>';
                include('./modulec_bx/uptime_lk.php');
                echo '</b><br /></div>';
            }
            ?>
        </div>
    </div>

</body>

</html>