public static class OAuth1Utilities
{
	private static readonly Lazy<bool[]> UnreservedCharacterMask = new Lazy<bool[]>(CreateUnreservedCharacterMask);

	public static string EncodeString(string value)
	{
		byte[] characterBytes = Encoding.UTF8.GetBytes(value);

		StringBuilder encoded = new StringBuilder();
		foreach (byte character in characterBytes)
		{
			if (UnreservedCharacterMask.Value[character])
			{
				encoded.Append((char)character);
			}
			else
			{
				encoded.Append($"%{character:X2}");
			}
		}

		return encoded.ToString();
	}

	public static string GetBaseStringUri(HttpRequest request)
	{
		StringBuilder baseStringUri = new StringBuilder();
		baseStringUri.Append(request.Scheme.ToLowerInvariant());
		baseStringUri.Append("://");
		baseStringUri.Append(request.Host.ToString().ToLowerInvariant());
		baseStringUri.Append(request.Path.ToString().ToLowerInvariant());
		return baseStringUri.ToString();
	}

	public static string GetNormalizedParameterString(HttpRequest request)
	{
		var parameters = new List<(string key, string value)>();

		foreach (var queryItem in request.Query)
		{
			foreach (var queryValue in queryItem.Value)
			{
				parameters.Add((queryItem.Key, queryValue));
			}
		}

		foreach (var formItem in request.Form)
		{
			foreach (var formValue in formItem.Value)
			{
				parameters.Add((formItem.Key, formValue));
			}
		}

		parameters.RemoveAll(_ => _.key == "oauth_signature");

		parameters = parameters
			.Select(_ => (key: EncodeString(_.key), value: EncodeString(_.value)))
			.OrderBy(_ => _.key)
			.ThenBy(_ => _.value).ToList();

		return string.Join("&", parameters.Select(_ => $"{_.key}={_.value}"));
	}

	public static string GetSignature(HttpRequest request, string clientSharedSecret, string tokenSharedSecret)
	{
		string signatureBaseString = GetSignatureBaseString(request);
		return GetSignature(signatureBaseString, clientSharedSecret, tokenSharedSecret);
	}

	public static string GetSignature(string signatureBaseString, string clientSharedSecret, string tokenSharedSecret)
	{
		string key = $"{EncodeString(clientSharedSecret)}&{EncodeString(tokenSharedSecret)}";
		var signatureAlgorithm = new HMACSHA1(Encoding.ASCII.GetBytes(key));
		byte[] digest = signatureAlgorithm.ComputeHash(Encoding.ASCII.GetBytes(signatureBaseString));
		return Convert.ToBase64String(digest);
	}

	public static string GetSignatureBaseString(HttpRequest request)
	{
		StringBuilder signatureBaseString = new StringBuilder();
		signatureBaseString.Append(request.Method.ToUpperInvariant());
		signatureBaseString.Append("&");
		signatureBaseString.Append(EncodeString(GetBaseStringUri(request)));
		signatureBaseString.Append("&");
		signatureBaseString.Append(EncodeString(GetNormalizedParameterString(request)));
		return signatureBaseString.ToString();
	}

	public static bool VerifySignature(HttpRequest request, string clientSharedSecret, string tokenSharedSecret)
	{
		string actualSignature = request.Form["oauth_signature"];
		string expectedSignature = GetSignature(request, clientSharedSecret, tokenSharedSecret);
		return expectedSignature == actualSignature;
	}

	private static bool[] CreateUnreservedCharacterMask()
	{
		bool[] mask = new bool[byte.MaxValue];

		// hyphen
		mask[45] = true;

		// period
		mask[46] = true;

		// 0-9
		for (int pos = 48; pos <= 57; pos++)
		{
			mask[pos] = true;
		}

		// A-Z
		for (int pos = 65; pos <= 90; pos++)
		{
			mask[pos] = true;
		}

		// underscore
		mask[95] = true;

		// a-z
		for (int pos = 97; pos <= 122; pos++)
		{
			mask[pos] = true;
		}

		// tilde
		mask[126] = true;

		return mask;
	}
}
