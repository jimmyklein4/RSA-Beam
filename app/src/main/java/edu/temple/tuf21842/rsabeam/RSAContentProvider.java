package edu.temple.tuf21842.rsabeam;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.util.Enumeration;

public class RSAContentProvider extends ContentProvider {
    public static final Uri CONTENT_URI = Uri.parse("content://edu.temple.tuf21842.rsabeam.provider");

    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;
    private SharedPreferences preferences;
    private String privateKey = "";
    private String publicKey = "";
    private SharedPreferences pref;
    private final String TAG = "RSAContentProvider";

    public RSAContentProvider() {
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // Implement this to handle requests to delete one or more rows.
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public String getType(Uri uri) {
        // TODO: Implement this to handle requests for the MIME type of the data
        // at the given URI.
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO: Implement this to handle requests to insert a new row.
        throw new UnsupportedOperationException("Not yet implemented");
    }


    //TODO: Save keys and move this stuff to update
    @Override
    public boolean onCreate() {
        pref = getContext().getSharedPreferences("edu.temple.tuf21842.rsa", Context.MODE_PRIVATE);


        // TODO: Implement this to initialize your content provider on startup.
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        MatrixCursor matrixCursor = new MatrixCursor(new String[]{"private","public"});
        matrixCursor.addRow(new Object[]{privateKey,publicKey});
        return matrixCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA);
            keyPair = keyPairGenerator.genKeyPair();
            privateKey = Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.NO_WRAP);
            publicKey = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP);

            SharedPreferences.Editor editor = pref.edit();
            editor.putString(getContext().getString(R.string.PRIVATE_KEY), privateKey);
            editor.putString(getContext().getString(R.string.PUBLIC_KEY), publicKey);
            editor.apply();

            //Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        } catch (Exception e) {
            Log.d(TAG, e.toString());
        }
        return 1;
    }
}
