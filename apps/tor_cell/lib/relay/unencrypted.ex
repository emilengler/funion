defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            data: nil

  defp decode_cmd(cmd) do
    case cmd do
      1 -> :begin
      4 -> :connected
    end
  end

  defp decode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.Relay.Begin.decode(data)
      :connected -> TorCell.Relay.Connected.decode(data)
    end
  end

  defp decode(payload, context) do
    <<cmd, padding::binary>> = payload
    cmd = decode_cmd(cmd)
    <<recognized::16, padding::binary>> = padding
    <<stream_id::16, padding::binary>> = padding
    <<digest::binary-size(4), padding::binary>> = padding
    <<length::16, padding::binary>> = padding
    <<data::binary-size(length), padding::binary>> = padding
    data = decode_data(cmd, data)
    true = byte_size(padding) == 509 - 11 - length

    # The context with this cell's payload but digest set to zero
    tmp_context = TorCrypto.Digest.update(context, modify_digest(payload, <<0::32>>))

    if is_decrypted?(recognized, digest, tmp_context) do
      {
        true,
        %TorCell.Relay.Unencrypted{cmd: cmd, stream_id: stream_id, data: data},
        TorCrypto.Digest.update(context, payload)
      }
    else
      {false, %TorCell.Relay{onion_skin: payload}, context}
    end
  end

  defp encode_cmd(cmd) do
    case cmd do
      :begin -> <<1>>
      :connected -> <<4>>
    end
  end

  defp encode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.Relay.Begin.encode(data)
      :connected -> TorCell.Relay.Connected.encode(data)
    end
  end

  defp encode(cell, context) do
    encoded_data = encode_data(cell.cmd, cell.data)
    padding_len = 509 - 11 - byte_size(encoded_data)

    encoded =
      encode_cmd(cell.cmd) <>
        <<0::16>> <>
        <<cell.stream_id::16>> <>
        <<0::32>> <>
        <<byte_size(encoded_data)::16>> <>
        encoded_data <>
        <<0::integer-size(padding_len)-unit(8)>>

    # The context with this cell's payload but digest set to zero
    tmp_context = TorCrypto.Digest.update(context, encoded)
    encoded = modify_digest(encoded, <<TorCrypto.Digest.calculate(tmp_context)::binary-size(4)>>)

    {encoded, TorCrypto.Digest.update(context, encoded)}
  end

  defp is_decrypted?(recognized, digest, context) do
    recognized == 0 && is_valid_digest?(digest, context)
  end

  defp is_valid_digest?(digest, context) do
    <<TorCrypto.Digest.calculate(context)::binary-size(4)>> == digest
  end

  defp modify_digest(payload, digest) do
    <<prefix::binary-size(5), suffix::binary>> = payload
    <<_::binary-size(4), suffix::binary>> = suffix
    prefix <> <<digest::binary-size(4)>> <> suffix
  end

  @doc """
  Decrypts a TorCell.Relay by removing length(keys) onion skins from it.

  TODO: Document return values
  """
  def decrypt(cell, context, keys) do
    decode(TorCrypto.OnionSkin.decrypt(cell.onion_skin, keys), context)
  end

  @doc """
  Encrypts a TorCell.Relay by encoding it and adding length(keys) onion skins to it.

  TODO: Document return values
  """
  def encrypt(cell, context, keys) do
    {encoded, context} = encode(cell, context)
    {%TorCell.Relay{onion_skin: TorCrypto.OnionSkin.encrypt(encoded, keys)}, context}
  end
end
