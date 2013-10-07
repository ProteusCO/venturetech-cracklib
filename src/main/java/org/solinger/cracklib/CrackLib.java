package org.solinger.cracklib;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.EnumSet;
import java.util.Set;

/*

 *solinger-cracklib-0.5.2 (06 Mar 2012)

  31 Jan 2011; Ken Logan <ken@i2rd.com> : CrackLib.java
  Generate a nicer IOException message when failing to initialize due to java.io.tmpdir misconfiguration.
  
*solinger-cracklib-0.5.1 (29 Oct 2007)

  29 Oct 2007; Pat Double <double@i2rd.com> : CrackLib.java
  Remove temporary files after opening to keep temporary directory
  from filling up.

 */

/**
 * A library to check passwords with emphasis on reverse engineering to a
 * dictionary word.
 * 
 * @author Justin F. Chapweske
 * @author Pat B. Double (double@i2rd.com)
 */
public class CrackLib
{
    /** Minimum number of different characters. */
    public static final int MINDIFF = 5;
    /** Minimum password length. */
    public static final int MINLEN = 6;
    /** Transformation rules. */
    static final String[] destructors = new String[]{
            ":", // noop - must do this to test raw word.
            "[", // trimming leading/trailing junk
            "]",
            "[[",
            "]]",
            "[[[",
            "]]]",
            "/?p@?p", // purging out punctuation/symbols/junk
            "/?s@?s",
            "/?X@?X",
            // attempt reverse engineering of password strings
            "/$s$s", "/$s$s/0s0o", "/$s$s/0s0o/2s2a", "/$s$s/0s0o/2s2a/3s3e",
            "/$s$s/0s0o/2s2a/3s3e/5s5s", "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i/4s4a",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1i/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l/4s4a",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/1s1l/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/4s4a", "/$s$s/0s0o/2s2a/3s3e/5s5s/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/5s5s/4s4a", "/$s$s/0s0o/2s2a/3s3e/5s5s/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/1s1i", "/$s$s/0s0o/2s2a/3s3e/1s1l",
            "/$s$s/0s0o/2s2a/3s3e/1s1i/4s4a", "/$s$s/0s0o/2s2a/3s3e/1s1i/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/1s1l/4s4a", "/$s$s/0s0o/2s2a/3s3e/1s1l/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/4s4a", "/$s$s/0s0o/2s2a/3s3e/4s4h",
            "/$s$s/0s0o/2s2a/3s3e/4s4a", "/$s$s/0s0o/2s2a/3s3e/4s4h",
            "/$s$s/0s0o/2s2a/5s5s", "/$s$s/0s0o/2s2a/5s5s/1s1i",
            "/$s$s/0s0o/2s2a/5s5s/1s1l", "/$s$s/0s0o/2s2a/5s5s/1s1i/4s4a",
            "/$s$s/0s0o/2s2a/5s5s/1s1i/4s4h", "/$s$s/0s0o/2s2a/5s5s/1s1l/4s4a",
            "/$s$s/0s0o/2s2a/5s5s/1s1l/4s4h", "/$s$s/0s0o/2s2a/5s5s/4s4a",
            "/$s$s/0s0o/2s2a/5s5s/4s4h", "/$s$s/0s0o/2s2a/5s5s/4s4a",
            "/$s$s/0s0o/2s2a/5s5s/4s4h", "/$s$s/0s0o/2s2a/1s1i",
            "/$s$s/0s0o/2s2a/1s1l", "/$s$s/0s0o/2s2a/1s1i/4s4a",
            "/$s$s/0s0o/2s2a/1s1i/4s4h", "/$s$s/0s0o/2s2a/1s1l/4s4a",
            "/$s$s/0s0o/2s2a/1s1l/4s4h", "/$s$s/0s0o/2s2a/4s4a",
            "/$s$s/0s0o/2s2a/4s4h", "/$s$s/0s0o/2s2a/4s4a",
            "/$s$s/0s0o/2s2a/4s4h", "/$s$s/0s0o/3s3e", "/$s$s/0s0o/3s3e/5s5s",
            "/$s$s/0s0o/3s3e/5s5s/1s1i", "/$s$s/0s0o/3s3e/5s5s/1s1l",
            "/$s$s/0s0o/3s3e/5s5s/1s1i/4s4a", "/$s$s/0s0o/3s3e/5s5s/1s1i/4s4h",
            "/$s$s/0s0o/3s3e/5s5s/1s1l/4s4a", "/$s$s/0s0o/3s3e/5s5s/1s1l/4s4h",
            "/$s$s/0s0o/3s3e/5s5s/4s4a", "/$s$s/0s0o/3s3e/5s5s/4s4h",
            "/$s$s/0s0o/3s3e/5s5s/4s4a", "/$s$s/0s0o/3s3e/5s5s/4s4h",
            "/$s$s/0s0o/3s3e/1s1i", "/$s$s/0s0o/3s3e/1s1l",
            "/$s$s/0s0o/3s3e/1s1i/4s4a", "/$s$s/0s0o/3s3e/1s1i/4s4h",
            "/$s$s/0s0o/3s3e/1s1l/4s4a", "/$s$s/0s0o/3s3e/1s1l/4s4h",
            "/$s$s/0s0o/3s3e/4s4a", "/$s$s/0s0o/3s3e/4s4h",
            "/$s$s/0s0o/3s3e/4s4a", "/$s$s/0s0o/3s3e/4s4h", "/$s$s/0s0o/5s5s",
            "/$s$s/0s0o/5s5s/1s1i", "/$s$s/0s0o/5s5s/1s1l",
            "/$s$s/0s0o/5s5s/1s1i/4s4a", "/$s$s/0s0o/5s5s/1s1i/4s4h",
            "/$s$s/0s0o/5s5s/1s1l/4s4a", "/$s$s/0s0o/5s5s/1s1l/4s4h",
            "/$s$s/0s0o/5s5s/4s4a", "/$s$s/0s0o/5s5s/4s4h",
            "/$s$s/0s0o/5s5s/4s4a", "/$s$s/0s0o/5s5s/4s4h", "/$s$s/0s0o/1s1i",
            "/$s$s/0s0o/1s1l", "/$s$s/0s0o/1s1i/4s4a", "/$s$s/0s0o/1s1i/4s4h",
            "/$s$s/0s0o/1s1l/4s4a", "/$s$s/0s0o/1s1l/4s4h", "/$s$s/0s0o/4s4a",
            "/$s$s/0s0o/4s4h", "/$s$s/0s0o/4s4a", "/$s$s/0s0o/4s4h",
            "/$s$s/2s2a", "/$s$s/2s2a/3s3e", "/$s$s/2s2a/3s3e/5s5s",
            "/$s$s/2s2a/3s3e/5s5s/1s1i", "/$s$s/2s2a/3s3e/5s5s/1s1l",
            "/$s$s/2s2a/3s3e/5s5s/1s1i/4s4a", "/$s$s/2s2a/3s3e/5s5s/1s1i/4s4h",
            "/$s$s/2s2a/3s3e/5s5s/1s1l/4s4a", "/$s$s/2s2a/3s3e/5s5s/1s1l/4s4h",
            "/$s$s/2s2a/3s3e/5s5s/4s4a", "/$s$s/2s2a/3s3e/5s5s/4s4h",
            "/$s$s/2s2a/3s3e/5s5s/4s4a", "/$s$s/2s2a/3s3e/5s5s/4s4h",
            "/$s$s/2s2a/3s3e/1s1i", "/$s$s/2s2a/3s3e/1s1l",
            "/$s$s/2s2a/3s3e/1s1i/4s4a", "/$s$s/2s2a/3s3e/1s1i/4s4h",
            "/$s$s/2s2a/3s3e/1s1l/4s4a", "/$s$s/2s2a/3s3e/1s1l/4s4h",
            "/$s$s/2s2a/3s3e/4s4a", "/$s$s/2s2a/3s3e/4s4h",
            "/$s$s/2s2a/3s3e/4s4a", "/$s$s/2s2a/3s3e/4s4h", "/$s$s/2s2a/5s5s",
            "/$s$s/2s2a/5s5s/1s1i", "/$s$s/2s2a/5s5s/1s1l",
            "/$s$s/2s2a/5s5s/1s1i/4s4a", "/$s$s/2s2a/5s5s/1s1i/4s4h",
            "/$s$s/2s2a/5s5s/1s1l/4s4a", "/$s$s/2s2a/5s5s/1s1l/4s4h",
            "/$s$s/2s2a/5s5s/4s4a", "/$s$s/2s2a/5s5s/4s4h",
            "/$s$s/2s2a/5s5s/4s4a", "/$s$s/2s2a/5s5s/4s4h", "/$s$s/2s2a/1s1i",
            "/$s$s/2s2a/1s1l", "/$s$s/2s2a/1s1i/4s4a", "/$s$s/2s2a/1s1i/4s4h",
            "/$s$s/2s2a/1s1l/4s4a", "/$s$s/2s2a/1s1l/4s4h", "/$s$s/2s2a/4s4a",
            "/$s$s/2s2a/4s4h", "/$s$s/2s2a/4s4a", "/$s$s/2s2a/4s4h",
            "/$s$s/3s3e", "/$s$s/3s3e/5s5s", "/$s$s/3s3e/5s5s/1s1i",
            "/$s$s/3s3e/5s5s/1s1l", "/$s$s/3s3e/5s5s/1s1i/4s4a",
            "/$s$s/3s3e/5s5s/1s1i/4s4h", "/$s$s/3s3e/5s5s/1s1l/4s4a",
            "/$s$s/3s3e/5s5s/1s1l/4s4h", "/$s$s/3s3e/5s5s/4s4a",
            "/$s$s/3s3e/5s5s/4s4h", "/$s$s/3s3e/5s5s/4s4a",
            "/$s$s/3s3e/5s5s/4s4h", "/$s$s/3s3e/1s1i", "/$s$s/3s3e/1s1l",
            "/$s$s/3s3e/1s1i/4s4a", "/$s$s/3s3e/1s1i/4s4h",
            "/$s$s/3s3e/1s1l/4s4a", "/$s$s/3s3e/1s1l/4s4h", "/$s$s/3s3e/4s4a",
            "/$s$s/3s3e/4s4h", "/$s$s/3s3e/4s4a", "/$s$s/3s3e/4s4h",
            "/$s$s/5s5s", "/$s$s/5s5s/1s1i", "/$s$s/5s5s/1s1l",
            "/$s$s/5s5s/1s1i/4s4a", "/$s$s/5s5s/1s1i/4s4h",
            "/$s$s/5s5s/1s1l/4s4a", "/$s$s/5s5s/1s1l/4s4h", "/$s$s/5s5s/4s4a",
            "/$s$s/5s5s/4s4h", "/$s$s/5s5s/4s4a", "/$s$s/5s5s/4s4h",
            "/$s$s/1s1i", "/$s$s/1s1l", "/$s$s/1s1i/4s4a", "/$s$s/1s1i/4s4h",
            "/$s$s/1s1l/4s4a", "/$s$s/1s1l/4s4h", "/$s$s/4s4a", "/$s$s/4s4h",
            "/$s$s/4s4a", "/$s$s/4s4h", "/0s0o", "/0s0o/2s2a",
            "/0s0o/2s2a/3s3e", "/0s0o/2s2a/3s3e/5s5s",
            "/0s0o/2s2a/3s3e/5s5s/1s1i", "/0s0o/2s2a/3s3e/5s5s/1s1l",
            "/0s0o/2s2a/3s3e/5s5s/1s1i/4s4a", "/0s0o/2s2a/3s3e/5s5s/1s1i/4s4h",
            "/0s0o/2s2a/3s3e/5s5s/1s1l/4s4a", "/0s0o/2s2a/3s3e/5s5s/1s1l/4s4h",
            "/0s0o/2s2a/3s3e/5s5s/4s4a", "/0s0o/2s2a/3s3e/5s5s/4s4h",
            "/0s0o/2s2a/3s3e/5s5s/4s4a", "/0s0o/2s2a/3s3e/5s5s/4s4h",
            "/0s0o/2s2a/3s3e/1s1i", "/0s0o/2s2a/3s3e/1s1l",
            "/0s0o/2s2a/3s3e/1s1i/4s4a", "/0s0o/2s2a/3s3e/1s1i/4s4h",
            "/0s0o/2s2a/3s3e/1s1l/4s4a", "/0s0o/2s2a/3s3e/1s1l/4s4h",
            "/0s0o/2s2a/3s3e/4s4a", "/0s0o/2s2a/3s3e/4s4h",
            "/0s0o/2s2a/3s3e/4s4a", "/0s0o/2s2a/3s3e/4s4h", "/0s0o/2s2a/5s5s",
            "/0s0o/2s2a/5s5s/1s1i", "/0s0o/2s2a/5s5s/1s1l",
            "/0s0o/2s2a/5s5s/1s1i/4s4a", "/0s0o/2s2a/5s5s/1s1i/4s4h",
            "/0s0o/2s2a/5s5s/1s1l/4s4a", "/0s0o/2s2a/5s5s/1s1l/4s4h",
            "/0s0o/2s2a/5s5s/4s4a", "/0s0o/2s2a/5s5s/4s4h",
            "/0s0o/2s2a/5s5s/4s4a", "/0s0o/2s2a/5s5s/4s4h", "/0s0o/2s2a/1s1i",
            "/0s0o/2s2a/1s1l", "/0s0o/2s2a/1s1i/4s4a", "/0s0o/2s2a/1s1i/4s4h",
            "/0s0o/2s2a/1s1l/4s4a", "/0s0o/2s2a/1s1l/4s4h", "/0s0o/2s2a/4s4a",
            "/0s0o/2s2a/4s4h", "/0s0o/2s2a/4s4a", "/0s0o/2s2a/4s4h",
            "/0s0o/3s3e", "/0s0o/3s3e/5s5s", "/0s0o/3s3e/5s5s/1s1i",
            "/0s0o/3s3e/5s5s/1s1l", "/0s0o/3s3e/5s5s/1s1i/4s4a",
            "/0s0o/3s3e/5s5s/1s1i/4s4h", "/0s0o/3s3e/5s5s/1s1l/4s4a",
            "/0s0o/3s3e/5s5s/1s1l/4s4h", "/0s0o/3s3e/5s5s/4s4a",
            "/0s0o/3s3e/5s5s/4s4h", "/0s0o/3s3e/5s5s/4s4a",
            "/0s0o/3s3e/5s5s/4s4h", "/0s0o/3s3e/1s1i", "/0s0o/3s3e/1s1l",
            "/0s0o/3s3e/1s1i/4s4a", "/0s0o/3s3e/1s1i/4s4h",
            "/0s0o/3s3e/1s1l/4s4a", "/0s0o/3s3e/1s1l/4s4h", "/0s0o/3s3e/4s4a",
            "/0s0o/3s3e/4s4h", "/0s0o/3s3e/4s4a", "/0s0o/3s3e/4s4h",
            "/0s0o/5s5s", "/0s0o/5s5s/1s1i", "/0s0o/5s5s/1s1l",
            "/0s0o/5s5s/1s1i/4s4a", "/0s0o/5s5s/1s1i/4s4h",
            "/0s0o/5s5s/1s1l/4s4a", "/0s0o/5s5s/1s1l/4s4h", "/0s0o/5s5s/4s4a",
            "/0s0o/5s5s/4s4h", "/0s0o/5s5s/4s4a", "/0s0o/5s5s/4s4h",
            "/0s0o/1s1i", "/0s0o/1s1l", "/0s0o/1s1i/4s4a", "/0s0o/1s1i/4s4h",
            "/0s0o/1s1l/4s4a", "/0s0o/1s1l/4s4h", "/0s0o/4s4a", "/0s0o/4s4h",
            "/0s0o/4s4a", "/0s0o/4s4h", "/2s2a", "/2s2a/3s3e",
            "/2s2a/3s3e/5s5s", "/2s2a/3s3e/5s5s/1s1i", "/2s2a/3s3e/5s5s/1s1l",
            "/2s2a/3s3e/5s5s/1s1i/4s4a", "/2s2a/3s3e/5s5s/1s1i/4s4h",
            "/2s2a/3s3e/5s5s/1s1l/4s4a", "/2s2a/3s3e/5s5s/1s1l/4s4h",
            "/2s2a/3s3e/5s5s/4s4a", "/2s2a/3s3e/5s5s/4s4h",
            "/2s2a/3s3e/5s5s/4s4a", "/2s2a/3s3e/5s5s/4s4h", "/2s2a/3s3e/1s1i",
            "/2s2a/3s3e/1s1l", "/2s2a/3s3e/1s1i/4s4a", "/2s2a/3s3e/1s1i/4s4h",
            "/2s2a/3s3e/1s1l/4s4a", "/2s2a/3s3e/1s1l/4s4h", "/2s2a/3s3e/4s4a",
            "/2s2a/3s3e/4s4h", "/2s2a/3s3e/4s4a", "/2s2a/3s3e/4s4h",
            "/2s2a/5s5s", "/2s2a/5s5s/1s1i", "/2s2a/5s5s/1s1l",
            "/2s2a/5s5s/1s1i/4s4a", "/2s2a/5s5s/1s1i/4s4h",
            "/2s2a/5s5s/1s1l/4s4a", "/2s2a/5s5s/1s1l/4s4h", "/2s2a/5s5s/4s4a",
            "/2s2a/5s5s/4s4h", "/2s2a/5s5s/4s4a", "/2s2a/5s5s/4s4h",
            "/2s2a/1s1i", "/2s2a/1s1l", "/2s2a/1s1i/4s4a", "/2s2a/1s1i/4s4h",
            "/2s2a/1s1l/4s4a", "/2s2a/1s1l/4s4h", "/2s2a/4s4a", "/2s2a/4s4h",
            "/2s2a/4s4a", "/2s2a/4s4h", "/3s3e", "/3s3e/5s5s",
            "/3s3e/5s5s/1s1i", "/3s3e/5s5s/1s1l", "/3s3e/5s5s/1s1i/4s4a",
            "/3s3e/5s5s/1s1i/4s4h", "/3s3e/5s5s/1s1l/4s4a",
            "/3s3e/5s5s/1s1l/4s4h", "/3s3e/5s5s/4s4a", "/3s3e/5s5s/4s4h",
            "/3s3e/5s5s/4s4a", "/3s3e/5s5s/4s4h", "/3s3e/1s1i", "/3s3e/1s1l",
            "/3s3e/1s1i/4s4a", "/3s3e/1s1i/4s4h", "/3s3e/1s1l/4s4a",
            "/3s3e/1s1l/4s4h", "/3s3e/4s4a", "/3s3e/4s4h", "/3s3e/4s4a",
            "/3s3e/4s4h", "/5s5s", "/5s5s/1s1i", "/5s5s/1s1l",
            "/5s5s/1s1i/4s4a", "/5s5s/1s1i/4s4h", "/5s5s/1s1l/4s4a",
            "/5s5s/1s1l/4s4h", "/5s5s/4s4a", "/5s5s/4s4h", "/5s5s/4s4a",
            "/5s5s/4s4h", "/1s1i", "/1s1l", "/1s1i/4s4a", "/1s1i/4s4h",
            "/1s1l/4s4a", "/1s1l/4s4h", "/4s4a", "/4s4h", "/4s4a", "/4s4h"};
    /** Transformation rules. */
    static final String[] constructors = {":", "r", "d", "f", "dr", "fr", "rf"};

    /**
     * Attempt to turn a password into rawtext.
     * @param rawtext the rawtext.
     * @param password the password.
     * @return true if the password can be turned into the rawtext.
     */
    public static final boolean matchPasswordAndRawtext(String rawtext, String password)
    {
        /* use destructors to turn password into rawtext */
        /* note use of Reverse() to save duplicating all rules */
        String mp;
        for (int i = 0; i < destructors.length; i++)
        {
            if ((mp = Rules.mangle(password, destructors[i])) == null)
            {
                continue;
            }
            if (mp.equals(rawtext))
            {
                return true;
            }
            if (Rules.reverse(mp).equals(rawtext))
            {
                return true;
            }
        }
        for (int i = 0; i < constructors.length; i++)
        {
            if ((mp = Rules.mangle(rawtext, constructors[i])) == null)
            {
                continue;
            }
            if (mp.equals(rawtext))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Check password against rules.
     * @param p the packer holding the word list.
     * @param password the password.
     * @return Set of error codes.
     * @throws IOException if an I/O error occurs.
     */
    public static final Set<ErrorCode> check(Packer p, String password)
            throws IOException
    {
        Set<ErrorCode> result = EnumSet.noneOf(ErrorCode.class);
        if (password.length() < 4)
        {
            result.add(ErrorCode.SHORT);
        }
        if (password.length() < MINLEN)
        {
            result.add(ErrorCode.SHORT);
        }
        String junk = new String(password.substring(0, 1));
        for (int i = 1; i < password.length(); i++)
        {
            if (junk.indexOf(password.charAt(i)) == -1)
            {
                junk = junk + password.charAt(i);
            }
        }
        if (junk.length() < MINDIFF)
        {
            result.add(ErrorCode.DIFFERENT);
        }
        if ((password = password.trim()).length() == 0)
        {
            result.add(ErrorCode.WHITESPACE);
        }
        for (int i = 0; i < destructors.length; i++)
        {
            String mp;
            if ((mp = Rules.mangle(password, destructors[i])) == null)
            {
                continue;
            }
            if (p.find(mp) != -1)
            {
                result.add(ErrorCode.DICTIONARY);
            }
        }
        password = Rules.reverse(password);
        for (int i = 0; i < destructors.length; i++)
        {
            String mp;
            if ((mp = Rules.mangle(password, destructors[i])) == null)
            {
                continue;
            }
            if (p.find(mp) != -1)
            {
                result.add(ErrorCode.DICTIONARY);
            }
        }
        return result;
    }

    /**
     * Output usage to stderr.
     */
    public static final void usage()
    {
        System.err.println("CrackLib -check <dict> <word>");
    }

    /**
     * Main entry point.
     * 
     * @param args the arguments.
     * @throws Exception if an exception occurs.
     */
    public static void main(String[] args) throws Exception
    {
        if (args.length == 3 && args[0].equals("-check"))
        {
            Packer p = new Packer(args[1], "r");
            try
            {
                Set<ErrorCode> err = check(p, args[2]);
                if (err.size() > 0)
                {
                    System.out.println(err);
                }
                else
                {
                    System.out.println(args[2] + "looks good to me!");
                }
            }
            finally
            {
                p.close();
            }
        }
        else
        {
            usage();
            System.exit(1);
        }
    }

    /** The packer. */
    private Packer _packer;
    
    /**
     * Create a new instance using the default word list.
     * @throws IOException if the word list cannot be loaded.
     */
    public CrackLib() throws IOException
    {
        this("words.pack");
    }
    
    /**
     * Create a new instance.
     * @param wordlist the location of the word list, will try the file system and class path.
     * @throws IOException if the word list cannot be loaded.
     */
    public CrackLib(String wordlist) throws IOException
    {
        try
        {
            _packer = new Packer(wordlist, "r");
        }
        catch (FileNotFoundException fnf)
        {
            // file not found, check the classpath
            InputStream is = getClass().getResourceAsStream(wordlist+".pwd");
            if (is == null)
                throw fnf;
            is.close();
            // copy to temporary files
            File[] files = new File[3];
            int filesIndex = 0;
            for(String ext : new String[] { ".pwd", ".pwi", ".hwm" })
            {
                File tmpDir = new File(System.getProperty("java.io.tmpdir"));
                if(!(tmpDir.isDirectory() && tmpDir.canWrite()))
                {
                    throw new IOException("Cannot write to temp directory which is specified by java.io.tmpdir as " + System.getProperty("java.io.tmpdir") +
                            ". This is commonly specified on the command line using -Djava.io.tmpdir, please check your configuration. The directory should exist if running a simple standalone Java application.");
                }
                File f = File.createTempFile("cracklib", ext);

                files[filesIndex++] = f;
                FileOutputStream fos = new FileOutputStream(f);
                ReadableByteChannel cin = Channels.newChannel(getClass().getResourceAsStream(wordlist+ext));
                fos.getChannel().transferFrom(cin, 0, Long.MAX_VALUE);
                cin.close();
                fos.close();
            }
            _packer = new Packer(files[0].getCanonicalPath(), files[1].getCanonicalPath(), files[2].getCanonicalPath(), "r");
            for(File f : files)
                f.delete(); // if the OS is smart it'll keep the file open for us but remove when the process ends
        }
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected void finalize() throws Throwable
    {
        _packer.close();
        super.finalize();
    }
    
    /**
     * Check password against rules.
     * @param password the password.
     * @return Set of error codes.
     * @throws IOException if an I/O error occurs.
     */
    public Set<ErrorCode> check(String password) throws IOException
    {
        return check(_packer, password);
    }
}
