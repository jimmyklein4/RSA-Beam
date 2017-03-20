package edu.temple.tuf21842.rsabeam;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.nfc.Tag;
import android.nfc.tech.NfcF;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Parcelable;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import android.text.format.Time;
import android.widget.ToggleButton;

import javax.crypto.Cipher;

import static android.nfc.NdefRecord.createMime;

public class MainActivity extends Activity {

    private final String TAG = "MainActivity";
    private ContentResolver cr;
    private TextView publicKeyTextView;
    private EditText encryptField;
    private String publicKeyString = "";
    private String privateKeyString = "";
    private byte[] receivedPublicKey;
    private byte[] receivedMessage;
    private byte[] encrypted;
    private SharedPreferences pref;
    private NfcAdapter nfcAdapter;
    private Uri[] fileUris = new Uri[10];
    private FileUriCallback fileUriCallback;
    private boolean isSendingKeys=false;
    IntentFilter[] intentFiltersArray;
    String[][] techListsArray;
    PendingIntent pendingIntent;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);


        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            ndef.addDataType("text/plain");    /* Handles all MIME based dispatches.
                                       You should specify only the ones that you need. */
        }
        catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }
        intentFiltersArray = new IntentFilter[] {ndef, };

        techListsArray = new String[][] { new String[] { NfcF.class.getName() } };



        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        fileUriCallback = new FileUriCallback();
        nfcAdapter.setNdefPushMessageCallback(fileUriCallback, this);

        cr = getContentResolver();
        Button generate = (Button) findViewById(R.id.generate);
        final Button encrypt = (Button) findViewById(R.id.encrypt);
        final Button decrypt = (Button) findViewById(R.id.decrypt);
        ToggleButton send = (ToggleButton) findViewById(R.id.send_file);
        encryptField = (EditText) findViewById(R.id.textInput);
        publicKeyTextView = (TextView) findViewById(R.id.public_key);


        pref = this.getSharedPreferences("edu.temple.tuf21842.rsa", Context.MODE_PRIVATE);
        publicKeyString = pref.getString(getString(R.string.PUBLIC_KEY), "");
        privateKeyString = pref.getString(getString(R.string.PRIVATE_KEY), "");
        if(publicKeyString.length()!=0){
            publicKeyTextView.setText(publicKeyString);
        }

        generate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        cr.update(RSAContentProvider.CONTENT_URI, null, null,null);
                        Cursor c = cr.query(RSAContentProvider.CONTENT_URI, null, null, null, null);
                        c.moveToFirst();
                        publicKeyString = c.getString(1);
                        privateKeyString = c.getString(0);
                        keyHandler.sendEmptyMessage(0);
                    }
                }).start();
            }
        });

        encrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if(privateKeyString.length()==0) {
                    Toast.makeText(getApplicationContext(), "Key not generated", Toast.LENGTH_LONG).show();
                } else if(encryptField.getText().length()==0) {
                    Toast.makeText(getApplicationContext(), "No text to encrypt", Toast.LENGTH_LONG).show();
                } else {
                    try {
                        String textToEncrypt = encryptField.getText().toString();
                        byte[] key = Base64.decode(privateKeyString, Base64.NO_WRAP);
                        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
                        KeyFactory keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
                        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
                        encrypted = cipher.doFinal(textToEncrypt.getBytes());
                        Toast.makeText(getApplicationContext(), "Text has been encrypted", Toast.LENGTH_SHORT).show();
                    } catch(Exception e){
                        Log.d(TAG, e.toString());
                    }
                }
            }
        });

        decrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    byte[] key = Base64.decode(publicKeyString.getBytes(), Base64.NO_WRAP);
                    String message = decrypt(key, encrypted);
                    Toast.makeText(getApplicationContext(), "Original Text: " + message, Toast.LENGTH_LONG).show();
                } catch(Exception e){
                    Log.d(TAG, e.toString());
                }
            }
        });

        send.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                //On is for keys, off is for text
                isSendingKeys = isChecked;
                if(isChecked){

                } else {

                }
            }
        });

    }

    @Override
    protected void onPause(){
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);

    }

    @Override
    protected void onResume(){
        super.onResume();
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFiltersArray, techListsArray);
        Log.d(TAG, getIntent().getAction());

    }

    public void onNewIntent(Intent intent) {
        Log.d(TAG, intent.getAction());
        //Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        //do something with tagFromIntent
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(intent.getAction())) {
            Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                    NfcAdapter.EXTRA_NDEF_MESSAGES);
            NdefMessage msg = (NdefMessage) rawMsgs[0];

            if (msg.getRecords()[0].getPayload()[0] == 0) {
                Log.d(TAG, "Getting keys");
                receivedPublicKey = msg.getRecords()[1].getPayload();
                if (receivedMessage != null) {
                    String message = decrypt(receivedPublicKey, receivedMessage);
                    Toast.makeText(getApplicationContext(), "Original Text: " + message, Toast.LENGTH_LONG).show();

                }
            } else if (msg.getRecords()[0].getPayload()[0] == 1) {
                Log.d(TAG, "Getting text");
                receivedMessage = msg.getRecords()[1].getPayload();
                if (receivedPublicKey != null) {
                    String message = decrypt(receivedPublicKey, receivedMessage);
                    Toast.makeText(getApplicationContext(), "Original Text: " + message, Toast.LENGTH_LONG).show();
                }
            }
            Log.d(TAG, rawMsgs[0].toString());
        }
    }


    private Handler keyHandler = new Handler(new Handler.Callback() {
        @Override
        public boolean handleMessage(Message msg) {
            publicKeyTextView.setText(publicKeyString);
            return false;
        }
    });

    private String decrypt(byte[] key, byte[] message){
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, publicKey);
            String decryptedString = new String(decryptCipher.doFinal(message));
            return decryptedString;
        }catch(Exception e){
            Log.d(TAG, e.toString());
        }
        return null;
    }

    private class FileUriCallback implements  NfcAdapter.CreateNdefMessageCallback{
        public FileUriCallback(){

        }

//        @Override
//        public Uri[] createBeamUris(NfcEvent event){
//            try{
//                fileUris[0] = Uri.parse(pref.getString(getString(R.string.PUBLIC_KEY), ""));
//                Log.d(TAG, "HERE WE ARE");
//            } catch(Exception e){
//                Log.d(TAG, e.toString());
//            }
//            return fileUris;
//        }

        @Override
        public NdefMessage createNdefMessage(NfcEvent event){
//            Time time = new Time();
//            time.setToNow();
//            String text = ("Beam me up!\n\n" +
//                    "Beam Time: " + time.format("%H:%M:%S"));

            byte[] keyFlag = new byte[1];
            byte[] toSend;
            if(isSendingKeys){
                keyFlag[0] = 0;
                toSend = Base64.decode(publicKeyString, Base64.NO_WRAP);
            } else {
                keyFlag[0] = 1;
                toSend = encrypted;
            }
            NdefMessage msg = new NdefMessage(
                    new NdefRecord[] {
                            createMime("text/plain", keyFlag),
                            createMime(
                            "text/plain", toSend)


                            //,NdefRecord.createApplicationRecord("com.example.android.beam")
                    });
            return msg;
        }
    }
}
