defmodule TorCell.RelayCell.End do
  defstruct reason: nil,
            ip: nil,
            ttl: nil

  defp decode_reason(reason) do
    case reason do
      1 -> :misc
      2 -> :resolvefailed
      3 -> :connectrefused
      4 -> :exitpolicy
      5 -> :destroy
      6 -> :done
      7 -> :timeout
      8 -> :noroute
      9 -> :hibernating
      10 -> :internal
      11 -> :resourcelimit
      12 -> :connreset
      13 -> :torprotocol
      14 -> :notdirectory
    end
  end

  defp decode_exitpolicy4(payload) do
    <<ip4::binary-size(4), payload::binary>> = payload
    ip4 = List.to_tuple(:binary.bin_to_list(ip4))
    <<ttl::32, _::binary>> = payload
    %TorCell.RelayCell.End{reason: :exitpolicy, ip: ip4, ttl: ttl}
  end

  # TODO: Consider removing redundancy here
  defp decode_exitpolicy6(payload) do
    <<ip6::binary-size(16), payload::binary>> = payload
    ip6 = List.to_tuple(:binary.bin_to_list(ip6))
    <<ttl::32, _::binary>> = payload
    %TorCell.RelayCell.End{reason: :exitpolicy, ip: ip6, ttl: ttl}
  end

  defp decode_exitpolicy(payload) do
    # Operates on the remaining payload
    case byte_size(payload) do
      8 -> decode_exitpolicy4(payload)
      20 -> decode_exitpolicy6(payload)
    end
  end

  # TODO: Document this
  def decode(payload) do
    <<reason, payload::binary>> = payload
    reason = decode_reason(reason)

    if reason == :exitpolicy do
      decode_exitpolicy(payload)
    else
      %TorCell.RelayCell.End{reason: reason}
    end
  end

  defp encode_reason(reason) do
    case reason do
      :misc -> <<1>>
      :resolvefailed -> <<2>>
      :connectrefused -> <<3>>
      :exitpolicy -> <<4>>
      :destroy -> <<5>>
      :done -> <<6>>
      :timeout -> <<7>>
      :noroute -> <<8>>
      :hibernating -> <<9>>
      :internal -> <<10>>
      :resourcelimit -> <<11>>
      :connreset -> <<12>>
      :torprotocol -> <<13>>
      :notdirectory -> <<14>>
    end
  end

  defp encode_exitpolicy(ip, ttl) do
    true = tuple_size(ip) == 4 || tuple_size(ip) == 16
    :binary.list_to_bin(Tuple.to_list(ip)) <> <<ttl::32>>
  end

  # TODO: Document this
  def encode(cell) do
    if cell.reason == :exitpolicy do
      encode_reason(cell.reason) <> encode_exitpolicy(cell.ip, cell.ttl)
    else
      encode_reason(cell.reason)
    end
  end
end
