


#pragma once
#include <winternl.h>
#include <Windows.h>
#include <SubAuth.h>
#include <cstdlib>
#include <cstdint>
#include <limits>

namespace SysCall {

    constexpr auto time = __TIME__;
    constexpr auto seed = static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10 + static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600 + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;
    
#define _A 54059 /* a prime */
#define _B 76963 /* another prime */
    //#define C 86969 /* yet another prime */
#define FIRSTH 37 /* also prime */
    template<class T>
    constexpr unsigned long PETOOLSCALL SysCallDefaultHasher(T s)
    {
        unsigned long h = FIRSTH;
        //const int len = strlen(s);
        //int i = 0;
        while (*s) {
            h = (h * _A) ^ (s[0] * _B);
            s++;
        }
        return h; // or return h % C;
    }


#define HASH_OF(TOHASH) SysCall::SysCallDefaultHasher<const char*>(TOHASH)
#define HASH_OF_DEF(TOHASH) constexpr unsigned long cnstxpr_hash_##TOHASH = HASH_OF(#TOHASH);
#define HASH_OF_REF(TOHASH) cnstxpr_hash_##TOHASH

    // YOU MUST SET THIS BEFORE USING SYSCALLS!
    // NtTestAlert from ntdll.dll
    inline void* g_pNTTestAlertPtr = nullptr;

#define FORCE_RET_CALLS
#pragma optimize("", off)
    inline __declspec(noinline)  __declspec(naked) void* __cdecl _call_syscall_function_x86_internal()
    {
        // + 4 -> ret ebp save
        // + 8 -> o_ecx
        // + 12 -> o_edx
        // + 16 -> pstack
        // + 20 -> nstacksize
        // + 24 -> ret_storage
        // + 28 -> pop_stack
        // + 32 -> function address  
        // + 36 -> syscall value
        _asm {
            push ebp
            mov ebp, esp
            mov ecx, esp
            add ecx, 20 // get nstack
            mov ecx, [ecx]
            // modify function return info
            mov esi, esp
            add esi, 16 // get pstack
            mov esi, [esi]
            mov edi, esp
            sub edi, ecx
            // https://faydoc.tripod.com/cpu/movsb.htm
            cld // set df flag so movsb increments pointers (DF = 0)
            rep movsb // copy data 
            // okay our stack is set up
            // mov registers over, go to area, and call!
            mov ebx, esp
            add ebx, 32
            mov ebx, [ebx] // function address
            mov ecx, esp
            add ecx, 8
            mov ecx, [ecx]
            mov edx, esp
            add edx, 12
            mov edx, [edx]
            // go to bottom of copied stack
            mov edi, esp
            add edi, 20
            mov edi, [edi]

            // now lets call the function
            sub esp, edi
#if 1   // through a ret to be cool lol
            mov eax, function_return
            push eax // ret address

            mov eax, ebp
            add eax, 36
            mov eax, [eax]

            push ebx // function address
            ret // boom 
#else   // we are boring and call it normally...
            call ebx
#endif

        function_return:
            mov esp, ebp
                pop ebp
                ret
        }
    }

    /// <c>call_function_x86</c> 
    /// <summary> 
    /// Calls A x86 Function through a ret procedure call.
    /// Wrapper Functions are guaranteed not to touch xmm0+ float registers.
    /// Function calls requiring operands aquired in/out of the function should manually
    /// be placed on the stack before call of call_function_x86. Functional templates
    /// will automatically manage this behaviour. 
    /// NOTE : Structure return values are not 
    /// guaranteed to work. depending on compilation, register may be trashed from
    /// wrapper functions. 
    ///  </summary>
    /// <param name="pfunction"> Address of function to call </param>
    /// <param name="completed"> Returns whether the function was completed sucessfully </param>
    /// <param name="o_ecx"> value to place in the ecx register </param>
    /// <param name="o_edx"> Value to place in the edx register </param>
    /// <param name="pstack"> Pointer to the stack in which to call the function with </param>
    /// <param name="nstacksize"> Size of the stack (parameter size) </param>
    /// <param name="ret"> Holds the return value of the function </param>
    /// <returns> void (no return) </returns>
    _Ret_maybenull_ inline __declspec(noinline) void* __cdecl  call_syscall_function_x86(
        _In_ int nsyscallcode,
        _In_ bool& completed,
        _In_ void* o_ecx,
        _In_ void* o_edx,
        _In_reads_(nstacksize) void* pstack,
        _In_ int   nstacksize,
        _In_ unsigned long& ret)
    {
        completed = false;

        if (nstacksize > UINT8_MAX)
            return nullptr; // 1byte add opcode

        if (nsyscallcode == -1)
            return nullptr;

        // + 8 -> o_ecx
        // + 12 -> o_edx
        // + 16 -> pstack
        // + 20 -> nstacksize
        // + 24 -> ret_storage
        // + 28 -> pop_stack
        // + 32 -> function address
        // + 36 -> syscall value


        char* Wow64 = (char*)g_pNTTestAlertPtr + 5;

        unsigned long _ret = 0;
        _asm {
            push nsyscallcode
            push Wow64
            push 0
            push ret
            push nstacksize
            push pstack
            push o_edx
            push o_ecx
            call _call_syscall_function_x86_internal
            add esp, 32
            mov _ret, eax
        }
        ret = _ret;
        completed = true;
        return (void*)ret;
    }
#pragma optimize("", on)

    template <typename... Args>
    struct variadic_typedef
    {
        // this single type represents a collection of types,
        // as the template arguments it took to define it
    };

    template <typename... Args>
    struct convert_in_tuple
    {
        // base case, nothing special,
        // just use the arguments directly
        // however they need to be used
        typedef std::tuple<Args...> type;
    };

    template <typename... Args>
    struct convert_in_tuple<variadic_typedef<Args...>>
    {
        // expand the variadic_typedef back into
        // its arguments, via specialization
        // (doesn't rely on functionality to be provided
        // by the variadic_typedef struct itself, generic)
        typedef typename convert_in_tuple<Args...>::type type;
    };

    template <typename ... Ts>
    constexpr std::size_t sum_size(std::tuple<Ts...> const&)
    {
        return (sizeof(Ts) + ...);
    }


    template<size_t I = 0, typename... Tp>
    void copy_tuple_arguments(std::tuple<Tp...>& t, int& nCurPos, void* pMemory) {
        auto val = std::get<I>(t);
        memcpy((char*)pMemory + nCurPos, &val, sizeof(val));
        nCurPos += sizeof(val);
        // do things
        if constexpr (I + 1 != sizeof...(Tp))
            copy_tuple_arguments<I + 1>(t, nCurPos, pMemory);
    }

    template<class function_params_t, typename ...A>
    void* get_arguements_from_tuple(void* pMem, int& nSize, A... args)
    {
        function_params_t funcargs = { args... };

        if constexpr (sizeof...(A) == 0) {
            nSize = 0;
        }
        else {
            nSize = sum_size(funcargs);

            if (!pMem)
                pMem = malloc(nSize);

            int nCurPos = 0;
            copy_tuple_arguments(funcargs, nCurPos, pMem);
        }
        return pMem;
    }

    template<class T, class function_params_t, typename ...A>
    T call_syscall_from_arg_pack(int nSyscall, A... args)
    {
        function_params_t funcargs = { args... };
        int nStackSize = 0;
        void* pMem = nullptr;
        void* pStack = nullptr;
        if constexpr (sizeof...(A) != 0) {
            nStackSize = sum_size<function_params_t>(funcargs);
            pMem = _malloca(nStackSize);
            pStack = get_arguements_from_tuple<function_params_t, A...>(pMem, nStackSize, args...);
        }

        bool disregard = false;
        unsigned long ret;
        call_syscall_function_x86(nSyscall, disregard, 0, 0, pStack, nStackSize, ret);
        _freea(pMem);
        if (!std::is_same<void, T>::value)
            return (T)ret;
    }

    inline int GetSysCodeFromFuncx86(unsigned char* pFunctionAddr)
    {
        pFunctionAddr++;
        return *(int32_t*)pFunctionAddr;
    }

    // user defined
    // handle getting the import func address yourself, then call GetSysCodeFromFunc
    // Make sure to insure read permissions on the page are set!
    int GetSysCodeForHash(unsigned long ulHash);

    template<class T>
    struct _windows_syscall_t;

#ifdef FORCE_RET_CALLS
#define CALLOP() return ret_call(args...);
#else
#define CALLOP() return call(args...);
#endif
#define MAKE_SYSCALL_FUNCTION_SPECIALIZED_TEMPLATE(CallConv)											\
	template<typename T, typename ...A>																	\
	struct _windows_syscall_t<T(CallConv* )(A...)>												        \
	{																									\
		using type = T(CallConv*)(A...);																\
        typedef variadic_typedef<A...> myTypes;                                                         \
        typedef convert_in_tuple<myTypes>::type function_params_t;                                      \
		_windows_syscall_t() {}																	        \
        [[maybe_unused]] _windows_syscall_t(int nCode, unsigned long ulhash) [[msvc::forceinline]] {    \
            if(nCode == -1)                                                                             \
                nCode = GetSysCodeForHash(ulhash);                                                      \
            m_nCode = nCode ^ seed;                                                                     \
        }                                                                                               \
        _windows_syscall_t(int nCode) {m_nCode = nCode ^ seed;}                                         \
		_windows_syscall_t(void* pfnFunction) [[msvc::forceinline]]	{}						            \
		_windows_syscall_t(const char* szFuncName, const char* szModule) [[msvc::forceinline]]			\
		{																								\
		}																								\
		_windows_syscall_t(unsigned long ulHash, const char* szModule) [[msvc::forceinline]]	        \
		{																								\
		}																								\
        __forceinline T CallConv ret_call(A... args){ return call_syscall_from_arg_pack                 \
                <T, function_params_t, A...>((int)(seed ^ (unsigned long)m_nCode), args...);}           \
		__forceinline T operator()(A... args) {CALLOP();}									            \
        __forceinline int get() { return  ((int)(seed ^ m_nCode)); }                                    \
		int m_nCode = -1;																	            \
	};

    MAKE_SYSCALL_FUNCTION_SPECIALIZED_TEMPLATE(__stdcall);

#define WINDOWS_SYSCALL_USE_HASH_DYNAMIC_FIND

#ifndef WINDOWS_SYSCALL_USE_HASH_DYNAMIC_FIND
#define WINDOWS_SYSCALL(Name, Type, Code) SysCall::_windows_syscall_t<Type> _##Name##(Code);
#define GLOBAL_WINDOWS_SYSCALL(Name, Type, Code) inline SysCall:: _windows_syscall_t<Type> g_##Name##(Code);
#else

#define WINDOWS_SYSCALL(Name, Type, Code)                                           \
    HASH_OF_DEF(Name);                                                              \
    SysCall::_windows_syscall_t<Type> _##Name##(-1, HASH_OF_REF(Name));             \

#define WINDOWS_SYSCALL_NO_HASH(Name, Type, Code)                                   \
    SysCall::_windows_syscall_t<Type> _##Name##(Code);                              \

#define GLOBAL_WINDOWS_SYSCALL(Name, Type, Code)                                   \
    HASH_OF_DEF(Name);                                                             \
    inline SysCall::_windows_syscall_t<Type> _##Name##(-1, HASH_OF_REF(Name));     \

#endif

}