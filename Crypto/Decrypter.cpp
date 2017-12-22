#include "stdafx.h"
#include "Decrypter.h"

int MyDecryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
{
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
		if (!CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
			return 8;
		}

		if (!CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
			return 9;
		}

		if (!CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
			return 10;
		}
	}

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
	dwBufferLen = dwBlockLen;

	if (!(pbBuffer = (PBYTE)malloc(dwBufferLen)))
	{
		return 11;
	}

	bool fEOF = false;
	do
	{
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			return 12;
		}

		if (dwCount <= dwBlockLen)
		{
			fEOF = TRUE;
		}

		if (!CryptDecrypt(
			hKey,
			0,
			fEOF,
			0,
			pbBuffer,
			&dwCount))
		{
			return 13;
		}

if (!WriteFile(
	hDestinationFile,
	pbBuffer,
	dwCount,
	&dwCount,
	NULL))
{
	return 14;
}

	} while (!fEOF);

	if (pbBuffer)
	{
		free(pbBuffer);
	}

	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	if (hHash)
	{
		if (!(CryptDestroyHash(hHash)))
		{
			return 14;
		}

		hHash = NULL;
	}

	if (hKey)
	{
		if (!(CryptDestroyKey(hKey)))
		{
			return 15;
		}
	}
 
	if (hCryptProv)
	{
		if (!(CryptReleaseContext(hCryptProv, 0)))
		{
			return 17;
		}
	}

	
	return 0;
}