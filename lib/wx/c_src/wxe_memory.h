/*
 * %CopyrightBegin%
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright Ericsson AB 2014-2025. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 */

#pragma once

#include <list>

class wxe_badarg final : public std::exception {
public:
  explicit wxe_badarg(int Ref) : ref(Ref) {}
  explicit wxe_badarg(const char *Var) : var(Var) {}
  int ref{};
  const char *var{};
};

class wxeMemEnv {
public:
  wxeMemEnv() {
    ref2ptr = static_cast<void **>(enif_alloc(128 * sizeof(void *)));
    ref2ptr[0] = nullptr;
    next = 1;
    max = 128;
    tmp_env = enif_alloc_env();
  }

  void *getPtr(ErlNifEnv *env, ERL_NIF_TERM term, const char *arg,
               ERL_NIF_TERM *type = nullptr) const {
    int index, tpl_sz;
    const ERL_NIF_TERM *tpl;
    if (!enif_get_tuple(env, term, &tpl_sz, &tpl) && tpl_sz != 4)
      throw wxe_badarg(arg);
    if (!enif_get_int(env, tpl[1], &index))
      throw wxe_badarg(arg);
    if (type)
      *type = tpl[2];
    void *temp = ref2ptr[index];
    if (index < next && (index == 0 || temp != nullptr))
      return temp;
    throw wxe_badarg(arg);
  }

  int next{};
  int max{};
  /// Array value owned by the emulator.
  void **ref2ptr{}; // TODO: Ownership/destruction?
  std::list<int> free;
  wxe_me_ref *me_ref{}; // backreference
  ErlNifPid owner{};
  ErlNifEnv *tmp_env{}; // TODO: Ownership/destruction?
};

class wxeRefData {
 public:
 wxeRefData(unsigned int dref, int ttype, int is_new, wxeMemEnv *menv) :
    ref(dref), type(ttype), memenv(menv), alloc_in_erl(is_new) { enif_set_pid_undefined(&pid); } ;
    int ref;
    int type;
    // 0 = wxWindow subclasses, 1 = wxObject subclasses
    // 2 = wxDialog subclasses, 3 = allocated wxObjects but not returned from new
    // 4 = wxGraphicsObjects or it's subclasses that can no be overloaded
    // 8 = wxObjects that should always be deleted directly (wxDC derivates)
    // > 10 classes which lack virtual destr, or are supposed to be allocated on
    //     the stack
    wxeMemEnv *memenv;
    bool alloc_in_erl;
    ErlNifPid pid;
};

// WX_DECLARE_HASH_MAP(ErlNifPid, wxeMemEnv*, wxIntegerHash, wxIntegerEqual, wxeMemMap);

WX_DECLARE_VOIDPTR_HASH_MAP(wxeRefData *, ptrMap);
