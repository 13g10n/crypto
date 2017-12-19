#include "stdafx.h"
#include "Decrypter.h"

int MyDecryptFile(
	LPTSTR pszSourceFile,
	LPTSTR pszDestinationFile,
	LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;

	HCRYPTPROV hCryptProv = NULL;

	DWORD dwCount;
	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;

	hSourceFile = CreateFile(
		pszSourceFile,
		FILE_READ_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{
		return 1;
	}

	hDestinationFile = CreateFile(
		pszDestinationFile,
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
		return 2;
	}

	if (!CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		0))
	{
		return 3;
	}

	if (!pszPassword || !pszPassword[0])
	{
		DWORD dwKeyBlobLen;
		PBYTE pbKeyBlob = NULL;

		if (!ReadFile(
			hSourceFile,
			&dwKeyBlobLen,
			sizeof(DWORD),
			&dwCount,
			NULL))
		{
			return 20;
		}

		if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen)))
		{
			return 21;
		}

		if (!ReadFile(
			hSourceFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
			return 22;
		}

		//-----------------------------------------------------------
		// Import the key BLOB into the CSP. 
		if (!CryptImportKey(
			hCryptProv,
			pbKeyBlob,
			dwKeyBlobLen,
			0,
			0,
			&hKey))
		{
			return 7;
		}

		if (pbKeyBlob)
		{
			free(pbKeyBlob);
		}
	}
	else
	{
		//-----------------------------------------------------------
		// Decrypt the file with a session key derived from a 
		// password. 

		//-----------------------------------------------------------
		// Create a hash object. 
		if (!CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
			/* MyHandleError(
				TEXT("Error during CryptCreateHash!\n"),
				GetLastError());
			goto Exit_MyDecryptFile; */
			return 8;
		}

		//-----------------------------------------------------------
		// Hash in the password data. 
		if (!CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
			/* MyHandleError(
				TEXT("Error during CryptHashData!\n"),
				GetLastError());
			goto Exit_MyDecryptFile; */
			return 9;
		}

		//-----------------------------------------------------------
		// Derive a session key from the hash object. 
		if (!CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
			/*MyHandleError(
				TEXT("Error during CryptDeriveKey!\n"),
				GetLastError());
			goto Exit_MyDecryptFile;*/
			return 10;
		}
	}

	//---------------------------------------------------------------
	// The decryption key is now available, either having been 
	// imported from a BLOB read in from the source file or having 
	// been created by using the password. This point in the program 
	// is not reached if the decryption key is not available.

	//---------------------------------------------------------------
	// Determine the number of bytes to decrypt at a time. 
	// This must be a multiple of ENCRYPT_BLOCK_SIZE. 

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	dwBufferLen = dwBlockLen;

	//---------------------------------------------------------------
	// Allocate memory for the file read buffer. 
	if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
	{
		/*MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
		goto Exit_MyDecryptFile;*/
		return 11;
	}

	//---------------------------------------------------------------
	// Decrypt the source file, and write to the destination file. 
	bool fEOF = false;
	do
	{
		//-----------------------------------------------------------
		// Read up to dwBlockLen bytes from the source file. 
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			/*MyHandleError(
				TEXT("Error reading from source file!\n"),
				GetLastError());
			goto Exit_MyDecryptFile;*/
			return 12;
		}

		if (dwCount <= dwBlockLen)
		{
			fEOF = TRUE;
		}

		//-----------------------------------------------------------
		// Decrypt the block of data. 
		if (!CryptDecrypt(
hKey,
0,
fEOF,
0,
pbBuffer,
&dwCount))
		{
		/*MyHandleError(
			TEXT("Error during CryptDecrypt!\n"),
			GetLastError());
		goto Exit_MyDecryptFile;*/
			return 13;
		}

//-----------------------------------------------------------
// Write the decrypted data to the destination file. 
if (!WriteFile(
	hDestinationFile,
	pbBuffer,
	dwCount,
	&dwCount,
	NULL))
{
	/*MyHandleError(
		TEXT("Error writing ciphertext.\n"),
		GetLastError());
	goto Exit_MyDecryptFile;*/
	return 14;
}

//-----------------------------------------------------------
// End the do loop when the last block of the source file 
// has been read, encrypted, and written to the destination 
// file.
	} while (!fEOF);

	fReturn = true;

Exit_MyDecryptFile:

	//---------------------------------------------------------------
	// Free the file read buffer.
	if (pbBuffer)
	{
		free(pbBuffer);
	}

	//---------------------------------------------------------------
	// Close files.
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	//-----------------------------------------------------------
	// Release the hash object. 
	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			/*MyHandleError(
				TEXT("Error during CryptDestroyHash.\n"),
				GetLastError());*/
			return 14;
		}

		hHash = NULL;
	}

	//---------------------------------------------------------------
	// Release the session key. 
	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			/*MyHandleError(
				TEXT("Error during CryptDestroyKey!\n"),
				GetLastError());*/
			return 15;
		}
	}

	//---------------------------------------------------------------
	// Release the provider handle. 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			/*MyHandleError(
				TEXT("Error during CryptReleaseContext!\n"),
				GetLastError());*/
			return 17;
		}
	}

	if (fReturn) {
		return 0;
	}
	else {
		return 99;
	}
}