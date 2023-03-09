module BalloonHashing

using SHA, Distributed

hash_functions = Dict(
    "sha1" => SHA.sha1,
    "sha224" => SHA.sha224,
    "sha256" => SHA.sha256,
    "sha384" => SHA.sha384,
    "sha512" => SHA.sha512,
    "sha3_224" => SHA.sha3_224,
    "sha3_256" => SHA.sha3_256,
    "sha3_384" => SHA.sha3_384,
    "sha3_512" => SHA.sha3_512,
)

const HASH_TYPE = "sha256"

"""
Convert Int to Vector{UInt8}.
"""
to_bytes(x)::Vector{UInt8} = reinterpret(UInt8, [x])

"""
Convert Vector{UInt8} to BigInt in little endian.
"""
function to_int(x::Vector{UInt8})::BigInt
    reverse!(x)
    hex = bytes2hex(x)
    return parse(BigInt, hex, base = 16)
end

"""
Concatenate all the arguments and hash the result.
Note that the hash function used can be modified
in the global parameter `HASH_TYPE`.
"""
function hash_func(args...)::Vector{UInt8}
    t = UInt8[]
    for arg in args
        if isa(arg, Int)
            t = [t; to_bytes(arg)]
        elseif isa(arg, Vector{UInt8})
            t = [t; arg]
        else
            t = [t; Vector{UInt8}(arg)]
        end
    end
    return hash_functions[HASH_TYPE](t)
end


"""
First step of the algorithm. Fill up a buffer with
pseudorandom bytes derived from the password and salt
by computing repeatedly the hash function on a combination
of the password and the previous hash.
"""
function expand(buf::Vector{Vector{UInt8}}, cnt::Int, space_cost::Int)::Int
    for s ∈ 2:space_cost
        push!(buf, hash_func(cnt, buf[s-1]))
        cnt += 1
    end
    return cnt
end

"""
Second step of the algorithm. Mix `time_cost` number
of times the pseudorandom bytes in the buffer. At each
step in the for loop, update the nth block to be
the hash of the n-1th block, the nth block, and `delta`
other blocks chosen at random from the buffer `buf`.
"""
function mix(
    buf::Vector{Vector{UInt8}},
    cnt::Int,
    delta::Int,
    salt::Vector{UInt8},
    space_cost::Int,
    time_cost::Int,
)::Nothing
    for t ∈ 1:time_cost
        for s ∈ 1:space_cost
            buf[s] = hash_func(cnt, s == 1 ? buf[end] : buf[s-1], buf[s])
            cnt += 1
            for i ∈ 1:delta
                idx_block = hash_func(t - 1, s - 1, i - 1)
                other = hash_func(cnt, salt, idx_block)
                other = to_int(other) % space_cost
                cnt += 1
                buf[s] = hash_func(cnt, buf[s], buf[other+1])
                cnt += 1
            end
        end
    end
end


"""
Final step. Return the last value in the buffer.
"""
function extract(buf::Vector{Vector{UInt8}})::Vector{UInt8}
    return buf[end]
end


"""
Main function that collects all the substeps. As
previously mentioned, first expand, then mix, and
finally extract. Note the result is returned as bytes,
for a more friendly function with default values
that returns a hex string, see the function `balloon_hash`.
"""
function balloon(
    password::AbstractString,
    salt::AbstractString,
    space_cost::Int,
    time_cost::Int,
    delta::Int = 3,
)::Vector{UInt8}
    salt_bytes = Vector{UInt8}(salt)
    buf = [hash_func(0, password, salt_bytes)]
    cnt = 1
    cnt = expand(buf, cnt, space_cost)
    mix(buf, cnt, delta, salt_bytes, space_cost, time_cost)
    return extract(buf)
end

"""
For internal use. Implements steps outlined in `balloon`.
"""
function _balloon(
    password::String,
    salt::Array{UInt8,1},
    space_cost::Int64,
    time_cost::Int64,
    delta::Int64 = 3,
)::Array{UInt8,1}
    buf = [hash_func(0, password, salt)]
    cnt = 1

    cnt = expand(buf, cnt, space_cost)
    mix(buf, cnt, delta, salt, space_cost, time_cost)
    return extract(buf)
end

"""
A more friendly client function that just takes
a password and a salt and outputs the hash as a hex string.
"""
function balloon_hash(password::String, salt::String)::String
    delta = 4
    time_cost = 20
    space_cost = 16
    return bytes2hex(balloon(password, salt, space_cost, time_cost, delta))
end


"""
M-core variant of the Balloon hashing algorithm. Note the result
is returned as bytes, for a more friendly function with default
values that returns a hex string, see the function `balloon_m_hash`.
"""
function balloon_m(
    password::String,
    salt::String,
    space_cost::Int64,
    time_cost::Int64,
    parallel_cost::Int64,
    delta::Int64 = 3,
)::Vector{UInt8}
    output = Vector{UInt8}()
    results = [output for _ ∈ 1:parallel_cost]
    @sync @distributed for p ∈ 1:parallel_cost
        parallel_salt = [Vector{UInt8}(salt); to_bytes(p)]
        results[p] = _balloon(password, parallel_salt, space_cost, time_cost, delta)
    end

    for result in results
        if length(output) == 0
            output = result
        else
            output = [a ⊻ b for (a, b) in zip(output, result)]
        end
    end

    return hash_func(password, salt, output)
end

"""
A more friendly client function that just takes
a password and a salt and outputs the hash as a hex string.
This uses the M-core variant of the Balloon hashing algorithm.
"""
function balloon_m_hash(password::String, salt::String)::String
    delta = 4
    time_cost = 20
    space_cost = 16
    parallel_cost = 4

    return bytes2hex(balloon_m(password, salt, space_cost, time_cost, parallel_cost, delta))
end

end
