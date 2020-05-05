// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider.test.staging;

import static com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider.INSTANCE;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TestStagedVersion {
    private static final Pattern VERSION_PATTERN = Pattern.compile("\\s*version\\s*=\\s*'(\\d+\\.\\d+\\.\\d+)'\\s*// Comment for TestStagedVersion to find.*");
    public static void main(String[] args) throws Exception {
	INSTANCE.assertHealthy();

	String expectedVersion = "";
	try (BufferedReader reader = new BufferedReader(new FileReader("../build.gradle"))) {
	    String line;
	    do {
		line = reader.readLine();
		Matcher m = VERSION_PATTERN.matcher(line);
		if (m.matches()) {
		    expectedVersion = m.group(1);
		    break;
		}
	    } while (line != null);
	}

	String version = INSTANCE.getVersionStr();
	if (!version.equals(expectedVersion)) {
	    throw new AssertionError(String.format("Expected version %s but got %s", expectedVersion, version));
	}

    }

}
