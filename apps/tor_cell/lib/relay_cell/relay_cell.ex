# SPDX-License-Identifier: ISC

defmodule TorCell.RelayCell do
  defstruct cmd: nil,
            stream_id: nil,
            data: nil

  defp decode_cmd(cmd) do
    case cmd do
      1 -> :begin
      2 -> :data
      3 -> :end
      4 -> :connected
      14 -> :extend2
      15 -> :extended2
    end
  end

  defp decode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.RelayCell.Begin.decode(data)
      :data -> TorCell.RelayCell.Data.decode(data)
      :end -> TorCell.RelayCell.End.decode(data)
      :connected -> TorCell.RelayCell.Connected.decode(data)
      :extend2 -> TorCell.RelayCell.Extend2.decode(data)
      :extended2 -> TorCell.RelayCell.Extended2.decode(data)
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
        %TorCell.RelayCell{cmd: cmd, stream_id: stream_id, data: data},
        TorCrypto.Digest.update(context, payload)
      }
    else
      {false, payload, context}
    end
  end

  defp encode_cmd(cmd) do
    case cmd do
      :begin -> <<1>>
      :data -> <<2>>
      :end -> <<3>>
      :connected -> <<4>>
      :extend2 -> <<14>>
      :extended2 -> <<15>>
    end
  end

  defp encode_data(cmd, data) do
    case cmd do
      :begin -> TorCell.RelayCell.Begin.encode(data)
      :data -> TorCell.RelayCell.Data.encode(data)
      :end -> TorCell.RelayCell.End.encode(data)
      :connected -> TorCell.RelayCell.Connected.encode(data)
      :extend2 -> TorCell.RelayCell.Extend2.encode(data)
      :extended2 -> TorCell.RelayCell.Extended2.encode(data)
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
  Decrypts an onion skin by removing length(streams) onion skins from it.

  TODO: Document return values
  """
  def decrypt(streams, context, onion_skin) do
    decode(TorCrypto.OnionSkin.decrypt(streams, onion_skin), context)
  end

  @doc """
  Encrypts a TorCell.RelayCell by encoding it and adding length(streams) onion skins to it.

  TODO: Document return values
  """
  def encrypt(streams, context, cell) do
    {encoded, context} = encode(cell, context)
    {TorCrypto.OnionSkin.encrypt(streams, encoded), context}
  end
end
