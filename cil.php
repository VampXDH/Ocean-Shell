<?php
class FileManager {
    private $rootDir;

    public function __construct($rootDir) {
        $this->rootDir = $rootDir;
    }

    public function listFiles($dir = '') {
        $dir = $this->rootDir . '/' . $dir;
        if (!is_dir($dir)) {
            return ['error' => 'Directory not found'];
        }
        $files = scandir($dir);
        $result = [];
        foreach ($files as $file) {
            if ($file == '.' || $file == '..') continue;
            $filepath = $dir . '/' . $file;
            $icon = is_dir($filepath) ? '📁' : '📄';
            $result[] = [
                'name' => $file,
                'icon' => $icon,
                'type' => is_dir($filepath) ? 'folder' : 'file',
                'path' => $filepath,
            ];
        }
        return $result;
    }

    public function createFile($filename, $content = '') {
        $filepath = $this->rootDir . '/' . $filename;
        if (file_exists($filepath)) {
            return ['error' => 'File already exists'];
        }
        file_put_contents($filepath, $content);
        return ['success' => 'File created'];
    }

    public function deleteFile($filename) {
        $filepath = $this->rootDir . '/' . $filename;
        if (!file_exists($filepath)) {
            return ['error' => 'File not found'];
        }
        unlink($filepath);
        return ['success' => 'File deleted'];
    }

    public function viewFile($filename) {
        $filepath = $this->rootDir . '/' . $filename;
        if (!file_exists($filepath)) {
            return ['error' => 'File not found'];
        }
        return ['content' => file_get_contents($filepath)];
    }

    public function uploadFile($filename, $tmp_name, $dir = '') {
        $dir = $this->rootDir . '/' . $dir;
        if (!is_dir($dir)) {
            return ['error' => 'Directory not found'];
        }
        $filepath = $dir . '/' . $filename;
        if (file_exists($filepath)) {
            return ['error' => 'File already exists'];
        }
        move_uploaded_file($tmp_name, $filepath);
        return ['success' => 'File uploaded'];
    }
}

// Usage
$fm = new FileManager(__DIR__);
$dir = isset($_GET['dir']) ? $_GET['dir'] : '';
if (isset($_FILES['file'])) {
    $result = $fm->uploadFile($_FILES['file']['name'], $_FILES['file']['tmp_name'], $dir);
    echo '<p>' . $result['success'] . '</p>';
}
$files = $fm->listFiles($dir);
?>
<!DOCTYPE html>
<html>
<head>
    <title>File Manager</title>
</head>
<body>
    <h1>File Manager</h1>
    <form enctype="multipart/form-data" method="post">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <ul>
    <?php foreach ($files as $file): ?>
        <?php if ($file['type'] == 'folder'): ?>
            <li><a href="?dir=<?= $dir . '/' . $file['name'] ?>"><?= $file['icon'] ?> <?= $file['name'] ?></a></li>
        <?php else: ?>
            <li><?= $file['icon'] ?> <a href="?view=<?= $dir . '/' . $file['name'] ?>"><?= $file['name'] ?></a></li>
        <?php endif; ?>
    <?php endforeach; ?>
    </ul>
    <?php if (isset($_GET['view'])):
        $content = $fm->viewFile($_GET['view']);
        if (isset($content['content'])): ?>
            <pre><?= htmlspecialchars($content['content']) ?></pre>
        <?php endif; ?>
    <?php endif; ?>
</body>
</html>
