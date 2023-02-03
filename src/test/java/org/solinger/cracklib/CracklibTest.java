/*
 * Copyright (c) Interactive Information R & D (I2RD) LLC.
 * All Rights Reserved.
 *
 * This software is confidential and proprietary information of
 * I2RD LLC ("Confidential Information"). You shall not disclose
 * such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with I2RD.
 */

package org.solinger.cracklib;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CracklibTest
{
    @Test()
    public void doConfirmMatchPrefixWorks() throws IOException
    {
        CrackLib crackLib = new CrackLib();
        Set<ErrorCode> res = crackLib.check("abase123Z");
        assertSame(1, res.size());
        assertTrue(res.contains(ErrorCode.DICTIONARY));
    }


    @Test()
    public void doConfirmMatchCaseInsensitiveWorks() throws IOException
    {
        CrackLib crackLib = new CrackLib();
        Set<ErrorCode> res = crackLib.check("aBase123Z");
        assertSame(1, res.size());
        assertTrue(res.contains(ErrorCode.DICTIONARY));
    }
}
