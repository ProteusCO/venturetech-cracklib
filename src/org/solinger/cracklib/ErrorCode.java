/*
 *  Copyright (c) Interactive Information R & D (I2RD) LLC.
 *  All Rights Reserved.
 *   
 *  This software is confidential and proprietary information of
 *  I2RD LLC ("Confidential Information"). You shall not disclose
 *  such Confidential Information and shall use it only in 
 *  accordance with the terms of the license agreement you entered
 *  into with I2RD.
 */
package org.solinger.cracklib;

/**
 * The error code response from a CrackLib check.
 * 
 * @author Pat B. Double (double@i2rd.com)
 */
public enum ErrorCode
{
    /** Password is too short. */
    SHORT,
    /** Not enough different characters. */
    DIFFERENT,
    /** All whitespace. */
    WHITESPACE,
    /** Based on dictionary word. */
    DICTIONARY;
}
