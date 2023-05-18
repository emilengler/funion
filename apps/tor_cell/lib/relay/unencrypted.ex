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

    # The new context with the (unencrypted) payload of this cell
    new_context = TorCrypto.Digest.update(context, payload)

    if is_decrypted?(recognized, digest, new_context) do
      {
        true,
        %TorCell.Relay.Unencrypted{cmd: cmd, stream_id: stream_id, data: data},
        new_context
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
    padding_len = 509 - 11 - byte_size(cell.data)

    encode_cmd(cell.cmd) <>
      <<0>> <>
      <<cell.stream_id::16>> <>
      <<TorCrypto.Digest.calculate(context)::binary-size(4)>> <>
      <<byte_size(cell.data)::16>> <>
      cell.data <>
      <<0::integer-size(padding_len)-unit(8)>>
  end

  defp is_decrypted?(recognized, digest, context) do
    recognized == 0 && is_valid_digest?(digest, context)
  end

  defp is_valid_digest?(digest, context) do
    <<TorCrypto.Digest.calculate(context)::binary-size(4)>> == digest
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
    encoded = encode(cell, context)
    context = TorCrypto.Digest.update(context, encoded)
    {%TorCell.Relay{onion_skin: TorCrypto.OnionSkin.encrypt(encoded, keys)}, context}
  end
end
