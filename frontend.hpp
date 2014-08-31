// 
// Copyright (c) 2002 David Eriksson <david@2good.nu>
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// $Id: frontend.hpp,v 1.3 2005/07/23 09:20:40 wjhengeveld Exp $
#ifndef _FRONTEND_HPP
#define _FRONTEND_HPP

#include "desquirr.hpp"

#include <stdarg.h>

class Frontend;
typedef boost::shared_ptr<Frontend> Frontend_ptr;

class Frontend
{
	public:
		virtual std::string RegisterName(RegisterIndex index) const = 0;
		virtual int vmsg(const char *format, va_list va) = 0;

		virtual Addr AddressFromName(const char *name, 
				Addr referer = INVALID_ADDR) = 0;

#if 0
		virtual Address GetStartAddress() = 0;
		virtual Function_ptr CreateFunction(Address address) = 0;
#endif

		static void Set(Frontend_ptr frontend);
		static Frontend& Get();
};

#endif

