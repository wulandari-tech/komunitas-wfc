const readlineSync = require('readline-sync');
const { execSync, exec } = require('child_process');

const url = readlineSync.question('Masukkan URL YouTube: ');
if (!url.startsWith('http')) {
    console.log('URL tidak valid.');
    process.exit();
}
console.log('\nMengambil daftar format...');
try {
    const formatList = execSync(`yt-dlp -F "${url}"`, { encoding: 'utf8' });
    console.log(formatList);
} catch (err) {
    console.log('Gagal mengambil format dari video.');
    process.exit();
}
const formatId = readlineSync.question('\nMasukkan format ID yang ingin didownload (contoh: 18 atau 140 atau 137+140): ');
if (!formatId) {
    console.log('Format ID tidak boleh kosong.');
    process.exit();
}
console.log('\nMendownload video...');
exec(`yt-dlp -f "${formatId}" --merge-output-format mp4 "${url}"`, (error, stdout, stderr) => {
    if (error) {
        console.error(`Terjadi kesalahan: ${error.message}`);
        return;
    }
    if (stderr && !stdout.includes('100%')) {
        console.error(`stderr: ${stderr}`);
        return;
    }
    console.log(`\nDownload selesai:\n${stdout}`);
});
