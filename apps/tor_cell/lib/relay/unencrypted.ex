defmodule TorCell.Relay.Unencrypted do
  defstruct cmd: nil,
            stream_id: nil,
            data: nil

  defp decode(payload, context) do
    <<cmd, padding::binary>> = payload
    <<recognized::16, padding::binary>> = padding
    <<stream_id::16, padding::binary>> = padding
    <<digest::binary-size(4), padding::binary>> = padding
    <<length::16, padding::binary>> = padding
    <<data::binary-size(length), padding::binary>> = padding
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
end
