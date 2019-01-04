# APK - Anti-debug
https://www.root-me.org/en/Challenges/Cracking/APK-Anti-debug
```
The goal is to find the password which validates the Android application.
```

According to the AndroidManifest.xml, there is only 1 activity in this app (**PuzzleActivity**), which is the main one (of course).<br>
This activity doesn't contain a lot of code:
```java
public class PuzzleActivity extends Activity {
    public EditText editTxt;
    public TextView txtView;
    public Validate valid;
    public Button validateBtn;

    /* renamed from: com.fortiguard.challenge.hashdays2012.challengeapp.PuzzleActivity$1 */
    class C00001 implements OnClickListener {
        C00001() {
        }

        public void onClick(View v) {
            PuzzleActivity.this.txtView.setText(Validate.checkSecret(PuzzleActivity.this.editTxt.getText().toString()));
            PuzzleActivity.this.editTxt.setEnabled(false);
            PuzzleActivity.this.validateBtn.setEnabled(false);
        }
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(C0001R.layout.main);
        this.validateBtn = (Button) findViewById(C0001R.id.validateButton);
        this.editTxt = (EditText) findViewById(C0001R.id.textArea);
        this.txtView = (TextView) findViewById(C0001R.id.textView1);
        this.valid = new Validate(getApplicationContext());
        this.validateBtn.setOnClickListener(new C00001());
    }
}
```
As you may notice, in the _onClick_ function there is a call to **Validate.checkSecret** function, which gets the password as an input. So, the password should be probably there (the name gives it):
```java
public static String checkSecret(String input) {
    try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        byte[] computedHash = digest.digest(input.getBytes());
        if (!computed) {
            convert2bytes();
        }
        for (int i = 0; i < hashes.length; i++) {
            if (Arrays.equals(computedHash, bh[i])) {
                return answers[i];
            }
        }
    } catch (Exception exp) {
        Log.w("Hashdays", "checkSecret: " + exp.toString());
    }
    return answers[4];
}
```
As you may see, the password getting hashed (using SHA-256 hashing) and get converted to hexstring.<br>
Next, it will compare the hash of the password to each hash stored in the **hashes** array.<br>
If the hash is equal to one of the hashes, then it will return an answer from the **answers** array, according to the index of the hash (in the **hashes** array).<br><br>

The **hashes** and **answers** arrays are
```java
    private static final String[] answers = new String[]{"Congrats from the FortiGuard team :)", "Nice try, but that would be too easy", "Ha! Ha! FortiGuard grin ;)", "Are you implying we are n00bs?", "Come on, this is a DEFCON conference!"};
    private static final String[] hashes = new String[]{"622a751d6d12b46ad74049cf50f2578b871ca9e9447a98b06c21a44604cab0b4", "301c4cd0097640bdbfe766b55924c0d5c5cc28b9f2bdab510e4eb7c442ca0c66", "d09e1fe7c97238c68e4be7b3cd64230c638dde1d08c656a1c9eaae30e49c4caf", "4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"};
```

It's pretty clear that we'll like to get the first item in **answers**, so we'll need to reverse the first hash in **hashes**.<br>
Using [this site](https://md5decrypt.net/en/Sha256/), the hash could be reversed easily to **MayTheF0rceB3W1thU**.<br>
After writing this password in the app, the app indeed displayed the _Congrats from the FortiGuard team :)_ message, and the challenge is solved (40 pts in root-me - doesn't worth it).
