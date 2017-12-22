#include "stdafx.h"
#include "Encrypter.h"


int MyEncryptFile(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, LPTSTR pszPassword)
{
	bool fReturn = false;
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hXchgKey = NULL;
	HCRYPTHASH hHash = NULL;

	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;

	PBYTE pbBuffer = NULL;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	DWORD dwCount;

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
		if (!CryptGenKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			KEYLENGTH | CRYPT_EXPORTABLE,
			&hKey))
		{
			return 4;
		}

		if (CryptGetUserKey(
			hCryptProv,
			AT_KEYEXCHANGE,
			&hXchgKey))
		{
		}
		else
		{
			if (NTE_NO_KEY == GetLastError())
			{
				if (!CryptGenKey(
					hCryptProv,
					AT_KEYEXCHANGE,
					CRYPT_EXPORTABLE,
					&hXchgKey))
				{
					return 5;
				}
			}
			else
			{
				return 6;
			}
		}

		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			NULL,
			&dwKeyBlobLen))
		{
		}
		else
		{
			return 7;
		}

		if (pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))
		{
		}
		else
		{
			return 8;
		}

		if (CryptExportKey(
			hKey,
			hXchgKey,
			SIMPLEBLOB,
			0,
			pbKeyBlob,
			&dwKeyBlobLen))
		{
		}
		else
		{
			return 9;
		}

		if (hXchgKey)
		{
			if (!(CryptDestroyKey(hXchgKey)))
			{
				return 10;
			}

			hXchgKey = 0;
		}
 
		if (!WriteFile(
			hDestinationFile,
			&dwKeyBlobLen,
			sizeof(DWORD),
			&dwCount,
			NULL))
		{
			return 11;
		}

		if (!WriteFile(
			hDestinationFile,
			pbKeyBlob,
			dwKeyBlobLen,
			&dwCount,
			NULL))
		{
			return 12;
		}

		free(pbKeyBlob);
	}
	else
	{
		if (CryptCreateHash(
			hCryptProv,
			CALG_MD5,
			0,
			0,
			&hHash))
		{
		}
		else
		{
			return 13;
		}
 
		if (CryptHashData(
			hHash,
			(BYTE *)pszPassword,
			lstrlen(pszPassword),
			0))
		{
		}
		else
		{
			return 14;
		}

		if (CryptDeriveKey(
			hCryptProv,
			ENCRYPT_ALGORITHM,
			hHash,
			KEYLENGTH,
			&hKey))
		{
		}
		else
		{
			return 15;
		}
	}

	dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

	if (ENCRYPT_BLOCK_SIZE > 1)
	{
		dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
	}
	else
	{
		dwBufferLen = dwBlockLen;
	}

	if (pbBuffer = (BYTE *)malloc(dwBufferLen))
	{
	}
	else
	{
		return 16;
	}

	bool fEOF = FALSE;
	do
	{
		if (!ReadFile(
			hSourceFile,
			pbBuffer,
			dwBlockLen,
			&dwCount,
			NULL))
		{
			//
			return 17;
		}

		if (dwCount < dwBlockLen)
		{
			fEOF = TRUE;
		}

		if (!CryptEncrypt(
			hKey,
			NULL,
			fEOF,
			0,
			pbBuffer,
			&dwCount,
			dwBufferLen))
		{
			return 18;
		}
 
		if (!WriteFile(
			hDestinationFile,
			pbBuffer,
			dwCount,
			&dwCount,
			NULL))
		{
			return 19;
		}

	} while (!fEOF);

	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	if (pbBuffer)
	{
		free(pbBuffer);
	}
 
	if (hHash)
	{
		CryptDestroyHash(hHash);
		hHash = NULL;
	}

	if (hKey)
	{
		CryptDestroyKey(hKey);
	}

	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
	}

	return 0;
} 