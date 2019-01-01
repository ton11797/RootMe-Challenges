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
  <li><b>.Main</b> acitity, which is the application's launcher.</li>
  <li><b>.ServiceStarter</b>, which recieves an intent when the boot is completed (probably for starting).</li>
  <li><b>.SDCardServiceStarter</b>, which recieves the intent <i>ACTION_EXTERNAL_APPLICATIONS_AVAILABLE</i> which getting broadcast soon after the boot is completed (probably for starting the service).</li>
  <li><b>.MainService</b>.</li>
  <li><b>org.torproject.android.service.TorService</b>, which recieves intents from a TOR service.</li>
</ol>
